"""Administrator 2FA is enforced by persistent challenges and sessions."""

from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from alba_security.admin_auth import (
    AdminAuth,
    AdminLoginChallenge,
    AdminSession,
    AuthenticationError,
    AuthenticationLocked,
)
from alba_security.models import Base


SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@pytest.fixture
def auth_context():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    moment = [datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)]
    password_hash = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1).hash("correct horse battery staple")
    auth = AdminAuth(
        username="administrator",
        password_hash=password_hash,
        totp_secret=SECRET,
        challenge_ttl_seconds=120,
        session_ttl_seconds=600,
        max_failed_attempts=3,
        lockout_seconds=180,
        clock=lambda: moment[0],
    )
    with Session(engine, expire_on_commit=False) as db:
        yield auth, db, moment
    engine.dispose()


def test_two_steps_are_required_and_secrets_are_hashed(auth_context):
    auth, db, moment = auth_context
    challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
    assert not auth.verify_session(db, challenge.challenge_token)
    stored_challenge = db.scalar(select(AdminLoginChallenge))
    assert stored_challenge.token_hash != challenge.challenge_token
    assert len(stored_challenge.token_hash) == 64

    code = pyotp.TOTP(SECRET).at(moment[0])
    issued = auth.complete_login(db, challenge.challenge_token, code)
    assert auth.verify_session(db, issued.access_token)
    stored_session = db.scalar(select(AdminSession))
    assert stored_session.token_hash != issued.access_token
    assert len(stored_session.token_hash) == 64

    with pytest.raises(AuthenticationError):
        auth.complete_login(db, challenge.challenge_token, code)
    assert auth.verify_session(db, issued.access_token)


def test_totp_cannot_be_reused_on_another_challenge(auth_context):
    auth, db, moment = auth_context
    first = auth.begin_login(db, "administrator", "correct horse battery staple")
    code = pyotp.TOTP(SECRET).at(moment[0])
    auth.complete_login(db, first.challenge_token, code)

    second = auth.begin_login(db, "administrator", "correct horse battery staple")
    with pytest.raises(AuthenticationError):
        auth.complete_login(db, second.challenge_token, code)
    moment[0] += timedelta(seconds=30)
    third = auth.begin_login(db, "administrator", "correct horse battery staple")
    assert auth.verify_session(db, auth.complete_login(db, third.challenge_token, pyotp.TOTP(SECRET).at(moment[0])).access_token)


def test_expiration_logout_and_failed_code_consumes_challenge(auth_context):
    auth, db, moment = auth_context
    challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
    with pytest.raises(AuthenticationError):
        auth.complete_login(db, challenge.challenge_token, "000000")
    with pytest.raises(AuthenticationError):
        auth.complete_login(db, challenge.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))

    valid = auth.begin_login(db, "administrator", "correct horse battery staple")
    issued = auth.complete_login(db, valid.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))
    assert auth.logout(db, issued.access_token)
    assert not auth.verify_session(db, issued.access_token)
    assert not auth.logout(db, issued.access_token)

    moment[0] += timedelta(seconds=30)
    fresh = auth.begin_login(db, "administrator", "correct horse battery staple")
    other = auth.complete_login(db, fresh.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))
    moment[0] += timedelta(seconds=601)
    assert not auth.verify_session(db, other.access_token)
    expired = auth.begin_login(db, "administrator", "correct horse battery staple")
    moment[0] += timedelta(seconds=121)
    with pytest.raises(AuthenticationError):
        auth.complete_login(db, expired.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))


def test_repeated_failures_lock_sign_in_until_timeout(auth_context):
    auth, db, moment = auth_context
    for _ in range(2):
        challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
        with pytest.raises(AuthenticationError):
            auth.complete_login(db, challenge.challenge_token, "000000")
    challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
    with pytest.raises(AuthenticationLocked):
        auth.complete_login(db, challenge.challenge_token, "000000")
    with pytest.raises(AuthenticationLocked):
        auth.begin_login(db, "administrator", "correct horse battery staple")

    moment[0] += timedelta(seconds=181)
    challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
    session = auth.complete_login(db, challenge.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))
    assert auth.verify_session(db, session.access_token)


def test_wrong_passwords_cannot_lock_administrator(auth_context):
    auth, db, moment = auth_context
    for _ in range(6):
        with pytest.raises(AuthenticationError):
            auth.begin_login(db, "administrator", "wrong password")
    challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
    session = auth.complete_login(db, challenge.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))
    assert auth.verify_session(db, session.access_token)


def test_password_step_does_not_reset_totp_failure_count(auth_context):
    auth, db, _moment = auth_context
    for attempt in range(3):
        challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
        error_type = AuthenticationLocked if attempt == 2 else AuthenticationError
        with pytest.raises(error_type):
            auth.complete_login(db, challenge.challenge_token, "not-a-code")
    with pytest.raises(AuthenticationLocked):
        auth.begin_login(db, "administrator", "correct horse battery staple")


def test_bogus_challenges_cannot_lock_administrator(auth_context):
    auth, db, moment = auth_context
    for index in range(6):
        with pytest.raises(AuthenticationError):
            auth.complete_login(db, f"invalid-challenge-{index}", "000000")
    challenge = auth.begin_login(db, "administrator", "correct horse battery staple")
    session = auth.complete_login(db, challenge.challenge_token, pyotp.TOTP(SECRET).at(moment[0]))
    assert auth.verify_session(db, session.access_token)


def test_configuration_fails_closed():
    with pytest.raises(RuntimeError):
        AdminAuth.from_environment({})
    hash_value = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1).hash("password")
    with pytest.raises(RuntimeError):
        AdminAuth("admin", hash_value, "JBSWY3DPEHPK3PXP")  # only 80 bits
