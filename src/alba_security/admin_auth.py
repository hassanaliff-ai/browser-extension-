"""Two-step administrator authentication backed by the application database.

The deployment supplies each administrator's Argon2id password hash and TOTP
secret. Password verification creates a short
lived challenge; only a fresh, unused TOTP can exchange it for a session.
Challenge and session secrets are never stored in plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import DateTime, Integer, String, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.models import Base, utc_now


class AdminAuthState(Base):
    """Persistent, shared throttle and TOTP replay state for the admin."""

    __tablename__ = "admin_auth_state"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_totp_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)


class AdminLoginChallenge(Base):
    __tablename__ = "admin_login_challenges"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    username: Mapped[str | None] = mapped_column(String(120))


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    username: Mapped[str | None] = mapped_column(String(120))


class AuthenticationError(Exception):
    """Invalid credentials, challenge, one-time code, or session."""


class AuthenticationLocked(AuthenticationError):
    """Too many failed sign-in attempts; retry after the lockout expires."""


@dataclass(frozen=True)
class IssuedChallenge:
    challenge_token: str
    expires_at: datetime


@dataclass(frozen=True)
class IssuedSession:
    access_token: str
    expires_at: datetime


def _utc(value: datetime) -> datetime:
    """SQLite drops timezone information; stored naive timestamps mean UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _positive_env_int(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name, str(default))
    try:
        value = int(raw)
    except (ValueError, TypeError) as error:
        raise RuntimeError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


class AdminAuth:
    """Owns administrator password, TOTP, lockout, and bearer sessions.

    Methods commit their own changes so failed attempts and consumed
    challenges remain recorded even when an HTTP request returns an error.
    Use one SQLAlchemy Session per request.
    """

    def __init__(
        self,
        username: str,
        password_hash: str,
        totp_secret: str,
        *,
        challenge_ttl_seconds: int = 300,
        session_ttl_seconds: int = 43_200,
        max_failed_attempts: int = 5,
        lockout_seconds: int = 900,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if not username or not password_hash.startswith("$argon2id$") or not totp_secret:
            raise RuntimeError("Administrator username, Argon2id hash, and TOTP secret are required")
        if not all(value > 0 for value in (
            challenge_ttl_seconds, session_ttl_seconds, max_failed_attempts, lockout_seconds
        )):
            raise RuntimeError("Administrator authentication timeouts and limits must be positive")
        try:
            decoded = base64.b32decode(totp_secret.upper(), casefold=True)
        except (ValueError, base64.binascii.Error) as error:
            raise RuntimeError("ADMIN_TOTP_SECRET must be valid base32") from error
        if len(decoded) < 20:
            raise RuntimeError("ADMIN_TOTP_SECRET must contain at least 160 bits of entropy")
        self.username = username
        self.state_id = "administrator"
        self.allow_legacy = True
        self.password_hash = password_hash
        self.totp = pyotp.TOTP(totp_secret.upper())
        self.challenge_ttl = timedelta(seconds=challenge_ttl_seconds)
        self.session_ttl = timedelta(seconds=session_ttl_seconds)
        self.max_failed_attempts = max_failed_attempts
        self.lockout = timedelta(seconds=lockout_seconds)
        self.clock = clock
        self.hasher = PasswordHasher()

    @classmethod
    def from_environment(cls, values: Mapping[str, str] | None = None) -> AdminAuth:
        env = os.environ if values is None else values
        return cls(
            username=env.get("ADMIN_USERNAME", ""),
            password_hash=env.get("ADMIN_PASSWORD_HASH", ""),
            totp_secret=env.get("ADMIN_TOTP_SECRET", ""),
            challenge_ttl_seconds=_positive_env_int(env, "ADMIN_CHALLENGE_TTL_SECONDS", 300),
            session_ttl_seconds=_positive_env_int(env, "ADMIN_SESSION_TTL_SECONDS", 43_200),
            max_failed_attempts=_positive_env_int(env, "ADMIN_MAX_FAILED_ATTEMPTS", 5),
            lockout_seconds=_positive_env_int(env, "ADMIN_LOCKOUT_SECONDS", 900),
        )

    def _state(self, db: Session) -> AdminAuthState:
        state = db.scalar(select(AdminAuthState).where(AdminAuthState.id == self.state_id).with_for_update().execution_options(populate_existing=True))
        if state is not None:
            return state
        state = AdminAuthState(id=self.state_id, failed_attempts=0, last_totp_counter=-1)
        db.add(state)
        try:
            db.flush()
        except IntegrityError:
            # A simultaneous first request may have inserted the singleton.
            db.rollback()
            state = db.scalar(select(AdminAuthState).where(AdminAuthState.id == self.state_id).with_for_update())
            if state is None:
                raise
        return state

    def _check_lockout(self, state: AdminAuthState, now: datetime) -> None:
        if state.locked_until is not None:
            if now < _utc(state.locked_until):
                raise AuthenticationLocked("Too many failed sign-in attempts")
            state.failed_attempts = 0
            state.locked_until = None

    def _fail(self, db: Session, state: AdminAuthState, now: datetime) -> None:
        state.failed_attempts += 1
        if state.failed_attempts >= self.max_failed_attempts:
            state.locked_until = now + self.lockout
        db.commit()
        if state.locked_until is not None:
            raise AuthenticationLocked("Too many failed sign-in attempts")
        raise AuthenticationError("Invalid administrator sign-in")

    def begin_login(self, db: Session, username: str, password: str) -> IssuedChallenge:
        """Verify password and issue an opaque, short-lived TOTP challenge."""
        now = _utc(self.clock())
        state = self._state(db)
        self._check_lockout(state, now)
        try:
            password_ok = self.hasher.verify(self.password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            password_ok = False
        # Verify the Argon2 hash even for a wrong username to avoid a quick
        # username-enumeration response path.
        username_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        if not password_ok or not username_ok:
            # Only someone who knows the password can obtain a challenge.
            # Counting arbitrary password guesses against the shared TOTP
            # lockout would let anyone deny service to the sole admin.
            raise AuthenticationError("Invalid administrator sign-in")
        token = secrets.token_urlsafe(32)
        expires_at = now + self.challenge_ttl
        db.add(AdminLoginChallenge(token_hash=_digest(token), expires_at=expires_at, username=self.username))
        db.commit()
        return IssuedChallenge(challenge_token=token, expires_at=expires_at)

    def _matching_totp_counter(self, code: str, now: datetime, last_used: int) -> int | None:
        if not re.fullmatch(r"[0-9]{6}", code):
            return None
        current = int(now.timestamp()) // self.totp.interval
        for counter in (current, current - 1, current + 1):
            if counter > last_used and hmac.compare_digest(code, self.totp.at(counter * self.totp.interval)):
                return counter
        return None

    def complete_login(self, db: Session, challenge_token: str, totp_code: str) -> IssuedSession:
        """Consume the challenge and a fresh TOTP, then issue a session."""
        now = _utc(self.clock())
        challenge = db.get(AdminLoginChallenge, _digest(challenge_token)) if challenge_token else None
        if challenge is None or challenge.consumed_at is not None or now >= _utc(challenge.expires_at):
            # An attacker without the password cannot obtain a valid opaque
            # challenge. Do not let arbitrary tokens lock the administrator.
            raise AuthenticationError("Invalid administrator sign-in")
        if challenge.username != self.username and not (self.allow_legacy and challenge.username is None):
            raise AuthenticationError("Invalid administrator sign-in")
        state = self._state(db)
        self._check_lockout(state, now)
        # One attempt per challenge keeps the six-digit second factor from
        # becoming an online guessing oracle. Claim it atomically: another
        # request may have consumed it after the initial read above.
        claimed = db.execute(
            update(AdminLoginChallenge)
            .where(
                AdminLoginChallenge.token_hash == challenge.token_hash,
                AdminLoginChallenge.consumed_at.is_(None),
                AdminLoginChallenge.expires_at > now,
            )
            .values(consumed_at=now)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            db.rollback()
            raise AuthenticationError("Invalid administrator sign-in")
        counter = self._matching_totp_counter(totp_code, now, state.last_totp_counter)
        if counter is None:
            self._fail(db, state, now)
        # Keep replay protection atomic on databases without row-level locks
        # too. The challenge and replay claim commit with the issued session.
        accepted = db.execute(
            update(AdminAuthState)
            .where(AdminAuthState.id == state.id, AdminAuthState.last_totp_counter < counter)
            .values(last_totp_counter=counter)
        )
        if accepted.rowcount != 1:
            self._fail(db, state, now)
        state.failed_attempts = 0
        state.locked_until = None
        token = secrets.token_urlsafe(32)
        expires_at = now + self.session_ttl
        db.add(AdminSession(token_hash=_digest(token), expires_at=expires_at, username=self.username))
        db.commit()
        return IssuedSession(access_token=token, expires_at=expires_at)

    def verify_session(self, db: Session, bearer_token: str) -> bool:
        """Return whether an unexpired, unrevoked second-factor session exists."""
        if not bearer_token:
            return False
        session = db.get(AdminSession, _digest(bearer_token))
        return bool(session and session.revoked_at is None and _utc(self.clock()) < _utc(session.expires_at)
                    and (session.username == self.username or (self.allow_legacy and session.username is None)))

    def logout(self, db: Session, bearer_token: str) -> bool:
        """Revoke a live session; returns False for missing/expired sessions."""
        if not self.verify_session(db, bearer_token):
            return False
        session = db.get(AdminSession, _digest(bearer_token))
        session.revoked_at = _utc(self.clock())
        db.commit()
        return True
