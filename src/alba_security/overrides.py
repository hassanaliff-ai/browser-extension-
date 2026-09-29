"""Audited, exact-match administrator exceptions for URL scan alerts.

The caller owns the database transaction. Creating or deactivating an
exception adds its audit row to the same Session before the caller commits.
An exception never changes the underlying risk score or findings.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, JSON, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.models import Base, new_id, utc_now


OverrideKind = Literal["domain", "url"]
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class Override(Base):
    """An exact hostname or exact URL exception, with no URL path stored."""

    __tablename__ = "admin_overrides"
    __table_args__ = (
        Index("ix_admin_overrides_match", "kind", "match_key", "active"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(6), nullable=False)
    # For URLs this is the SHA-256 digest of the *entire, exact* URL. For
    # domains it is the lowercase IDNA hostname. Raw URL paths are discarded.
    match_key: Mapped[str] = mapped_column(String(253), nullable=False)
    target_display: Mapped[str] = mapped_column(String(253), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deactivated_by: Mapped[str | None] = mapped_column(String(120))
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OverrideAudit(Base):
    """Append-only record of administrator changes to an exception."""

    __tablename__ = "admin_override_audit"
    __table_args__ = (Index("ix_admin_override_audit_created", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    override_id: Mapped[str] = mapped_column(ForeignKey("admin_overrides.id"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


def _utc(value: datetime) -> datetime:
    """Restore UTC for SQLite, which drops timezone information on read."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _hostname(value: str, *, domain_rule: bool) -> str:
    host = value.rstrip(".").lower()
    if not host:
        raise ValueError("A hostname is required")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Invalid hostname") from error
    if len(host) > 253:
        raise ValueError("Hostname is too long")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("Invalid hostname") from None
        if domain_rule and len(labels) < 2:
            raise ValueError("A domain exception requires a full domain name")
    else:
        if domain_rule:
            raise ValueError("Use an exact URL exception for an IP address")
    return host


def _url_identity(url: str) -> tuple[str, str]:
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError("URL must be between 1 and 4096 characters")
    # urlsplit silently removes some control characters. Reject them first so
    # the host shown to the administrator matches the string being hashed.
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 or char == "\\" for char in url):
        raise ValueError("URL cannot contain whitespace, controls, or backslashes")
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must be a valid HTTP(S) URL")
        _ = parsed.port  # Validate a supplied port.
        host = _hostname(parsed.hostname, domain_rule=False)
    except (UnicodeError, ValueError) as error:
        raise ValueError("URL must be a valid HTTP(S) URL") from error
    return hashlib.sha256(url.encode("utf-8")).hexdigest(), host


def _identity(kind: OverrideKind, target: str) -> tuple[str, str]:
    if kind == "url":
        return _url_identity(target)
    if kind == "domain":
        if not isinstance(target, str) or not target:
            raise ValueError("A domain is required")
        host = _hostname(target.strip(), domain_rule=True)
        return host, host
    raise ValueError("Exception kind must be 'domain' or 'url'")


def _required_text(value: str, name: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ValueError(f"{name} must be between 1 and {max_length} characters")
    cleaned = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in cleaned):
        raise ValueError(f"{name} cannot contain control characters")
    return cleaned


def _is_effective(item: Override, at: datetime) -> bool:
    return item.active and (item.expires_at is None or _utc(item.expires_at) > at)


def create_override(
    session: Session,
    kind: OverrideKind,
    target: str,
    reason: str,
    actor: str,
    expires_at: datetime | None = None,
) -> Override:
    """Stage an exception and creation audit in the caller's transaction.

    Raises ValueError for invalid input or a duplicate effective exception.
    No external notification is sent, and the URL itself is never persisted.
    """
    match_key, display = _identity(kind, target)
    reason = _required_text(reason, "Reason", 2000)
    actor = _required_text(actor, "Actor", 120)
    if re.search(r"https?://", reason, flags=re.IGNORECASE):
        raise ValueError("Reason must not contain a full URL")
    now = utc_now()
    if expires_at is not None:
        if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
            raise ValueError("Expiry must include a timezone")
        expires_at = expires_at.astimezone(timezone.utc)
        if expires_at <= now:
            raise ValueError("Expiry must be in the future")

    existing = session.scalars(
        select(Override).where(
            Override.kind == kind,
            Override.match_key == match_key,
            Override.active.is_(True),
        )
    ).all()
    if any(_is_effective(item, now) for item in existing):
        raise ValueError("An active exception already exists for this target")

    item = Override(
        kind=kind,
        match_key=match_key,
        target_display=display,
        reason=reason,
        active=True,
        created_by=actor,
        created_at=now,
        expires_at=expires_at,
    )
    session.add(item)
    session.flush()
    session.add(OverrideAudit(
        override_id=item.id,
        action="created",
        actor=actor,
        details={"kind": kind, "target_display": display, "reason": reason},
        created_at=now,
    ))
    session.flush()
    return item


def list_overrides(session: Session) -> list[Override]:
    """List current and historical exceptions, most recent first."""
    return list(session.scalars(
        select(Override).order_by(Override.created_at.desc(), Override.id.desc())
    ).all())


def deactivate_override(session: Session, override_id: str, actor: str) -> Override:
    """Stage a deactivation and audit in the caller's transaction.

    Raises LookupError if no such exception exists and ValueError if already
    inactive. Expired exceptions may still be explicitly deactivated.
    """
    actor = _required_text(actor, "Actor", 120)
    item = session.get(Override, override_id)
    if item is None:
        raise LookupError("Exception not found")
    if not item.active:
        raise ValueError("Exception is already inactive")
    now = utc_now()
    item.active = False
    item.deactivated_by = actor
    item.deactivated_at = now
    session.add(OverrideAudit(
        override_id=item.id,
        action="deactivated",
        actor=actor,
        details={"kind": item.kind, "target_display": item.target_display},
        created_at=now,
    ))
    session.flush()
    return item


def match_override(session: Session, url: str, at: datetime | None = None) -> Override | None:
    """Find an effective exact URL exception, then an exact host exception."""
    fingerprint, host = _url_identity(url)
    at = at or utc_now()
    if at.tzinfo is None:
        raise ValueError("Match time must include a timezone")
    at = at.astimezone(timezone.utc)
    for kind, key in (("url", fingerprint), ("domain", host)):
        items = session.scalars(
            select(Override)
            .where(Override.kind == kind, Override.match_key == key, Override.active.is_(True))
            .order_by(Override.created_at.desc(), Override.id.desc())
        ).all()
        for item in items:
            if _is_effective(item, at):
                return item
    return None
