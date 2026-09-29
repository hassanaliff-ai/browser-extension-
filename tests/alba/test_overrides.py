"""Tests for administrator exceptions and their audit trail."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from alba_security.models import Base, utc_now
from alba_security.overrides import (
    Override,
    OverrideAudit,
    create_override,
    deactivate_override,
    list_overrides,
    match_override,
)


@pytest.fixture
def engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def test_domain_override_matches_exact_hostname_only_and_is_audited(engine):
    with Session(engine) as session:
        item = create_override(session, "domain", "EXAMPLE.Org.", "Known training site", "admin-1")
        session.commit()
        assert item.match_key == "example.org"
        assert item.target_display == "example.org"

    with Session(engine) as session:
        assert match_override(session, "https://example.org/a?secret=1").id == item.id
        assert match_override(session, "https://EXAMPLE.ORG/other").id == item.id
        assert match_override(session, "https://sub.example.org/a") is None
        assert match_override(session, "https://example.org.evil.test/a") is None
        assert list_overrides(session)[0].id == item.id
        audit = session.scalars(select(OverrideAudit)).all()
        assert [(entry.action, entry.actor) for entry in audit] == [("created", "admin-1")]


def test_url_override_is_exact_and_never_persists_url_path_or_query(engine):
    private_url = "https://example.org/private-case-123?token=private-456"
    with Session(engine) as session:
        item = create_override(session, "url", private_url, "Documented false positive", "admin-2")
        session.commit()
        assert item.match_key == hashlib.sha256(private_url.encode()).hexdigest()
        assert item.target_display == "example.org"
        assert match_override(session, private_url).id == item.id
        assert match_override(session, "https://example.org/private-case-123?token=other") is None
        assert match_override(session, "https://example.org/other") is None

    with engine.connect() as connection:
        rows = connection.exec_driver_sql("SELECT match_key, target_display, reason FROM admin_overrides").all()
        audit_rows = connection.exec_driver_sql("SELECT details FROM admin_override_audit").all()
    stored = json.dumps([rows, audit_rows], default=str)
    assert "private-case-123" not in stored
    assert "private-456" not in stored


def test_expired_override_never_matches_and_can_be_replaced(engine):
    expiry = utc_now() + timedelta(hours=1)
    with Session(engine) as session:
        expired = create_override(session, "domain", "example.org", "Temporary exception", "admin-1", expiry)
        session.commit()
        assert match_override(session, "https://example.org", at=expiry - timedelta(seconds=1)).id == expired.id
        assert match_override(session, "https://example.org", at=expiry) is None

    with Session(engine) as session:
        with pytest.raises(ValueError, match="already exists"):
            create_override(session, "domain", "example.org", "Duplicate", "admin-2")

    # Simulate time passing without deleting history: an expired exception
    # no longer blocks a fresh administrator decision for the same domain.
    with Session(engine) as session:
        old = session.get(Override, expired.id)
        old.expires_at = utc_now() - timedelta(seconds=1)
        session.commit()
    with Session(engine) as session:
        replacement = create_override(session, "domain", "example.org", "Renewed exception", "admin-2")
        session.commit()
        assert replacement.id != expired.id
        assert match_override(session, "https://example.org").id == replacement.id
        assert len(list_overrides(session)) == 2


def test_deactivation_is_audited_and_transactional(engine):
    with Session(engine) as session:
        item = create_override(session, "domain", "example.org", "False positive", "admin-1")
        session.commit()
        item_id = item.id

    with Session(engine) as session:
        deactivated = deactivate_override(session, item_id, "admin-2")
        assert deactivated.active is False
        session.rollback()

    with Session(engine) as session:
        assert match_override(session, "https://example.org") is not None
        assert [record.action for record in session.scalars(select(OverrideAudit)).all()] == ["created"]
        deactivate_override(session, item_id, "admin-2")
        session.commit()

    with Session(engine) as session:
        assert match_override(session, "https://example.org") is None
        rows = session.scalars(select(OverrideAudit).order_by(OverrideAudit.created_at)).all()
        assert [row.action for row in rows] == ["created", "deactivated"]
        assert [row.actor for row in rows] == ["admin-1", "admin-2"]
        with pytest.raises(ValueError, match="already inactive"):
            deactivate_override(session, item_id, "admin-3")
        with pytest.raises(LookupError):
            deactivate_override(session, "missing", "admin-3")


@pytest.mark.parametrize("kind,target", [
    ("domain", "*.example.org"),
    ("domain", "example.org.evil test"),
    ("domain", "https://example.org/path"),
    ("domain", "org"),
    ("domain", "127.0.0.1"),
    ("url", "file:///private/file"),
    ("url", "https://example.org/bad path"),
    ("url", "https://example.org:bad/path"),
    ("url", "https://example.org\\@evil.test/path"),
])
def test_invalid_targets_are_rejected_without_audit(engine, kind, target):
    with Session(engine) as session:
        with pytest.raises(ValueError):
            create_override(session, kind, target, "Not safe", "admin-1")
        assert session.scalars(select(OverrideAudit)).all() == []


def test_reason_actor_and_expiry_are_validated(engine):
    with Session(engine) as session:
        with pytest.raises(ValueError, match="Reason"):
            create_override(session, "domain", "example.org", " ", "admin-1")
        with pytest.raises(ValueError, match="Actor"):
            create_override(session, "domain", "example.org", "False positive", " ")
        with pytest.raises(ValueError, match="full URL"):
            create_override(session, "domain", "example.org", "See https://example.org/private", "admin-1")
        with pytest.raises(ValueError, match="future"):
            create_override(session, "domain", "example.org", "False positive", "admin-1", utc_now() - timedelta(seconds=1))
        assert session.scalars(select(Override)).all() == []
