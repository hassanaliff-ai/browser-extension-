"""Durable monthly report generation and delivery tests."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import alba_security.overrides  # noqa: F401 — register override table before create_all
from alba_security.models import Base, Device, Scan
from alba_security.notifications import NotificationSettings
from alba_security.report_job import (
    MonthlyReportRecord,
    dispatch_monthly_report,
    prepare_monthly_report,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        session.add(Device(id="device-1", name="Private device"))
        session.add(Scan(
            device_id="device-1", target_kind="download",
            target_fingerprint="a" * 64, target_display="private-file",
            signals=[], score=90, severity="Critical", completeness="complete",
            created_at=datetime(2026, 9, 20, tzinfo=timezone.utc),
        ))
        session.commit()
        yield session
    engine.dispose()


def fake_llm():
    calls = []

    class Responses:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(output_text="One critical file scan requires administrator review.")

    return SimpleNamespace(responses=Responses()), calls


def test_prepare_is_idempotent_and_preserves_generated_report(db):
    client, calls = fake_llm()
    first = prepare_monthly_report(db, 2026, 9, llm_client=client, model="test-model")
    second = prepare_monthly_report(db, 2026, 9, llm_client=client, model="test-model")
    assert first.id == second.id
    assert len(calls) == 1
    assert db.scalar(select(func.count()).select_from(MonthlyReportRecord)) == 1
    assert first.period == "2026-09"
    assert first.status == "draft"
    assert first.stats["total_scans"] == 1
    assert first.stats["severity_counts"]["Critical"] == 1
    assert first.summary_source == "openai"
    assert first.sent_at is None


def test_successful_dispatch_is_saved_and_never_repeated(db):
    client, _ = fake_llm()
    report = prepare_monthly_report(db, 2026, 9, llm_client=client, model="test-model")
    deliveries = []
    settings = NotificationSettings(
        smtp_host="smtp.example", smtp_from="reports@example.org",
        admin_emails=("admin@example.org",),
    )
    first = dispatch_monthly_report(
        db, report, settings=settings,
        email_sender=lambda *args: deliveries.append(args),
    )
    assert first.status == "sent"
    assert first.sent_at is not None
    assert len(first.delivery_outcomes) == 1
    assert first.delivery_outcomes[0]["status"] == "sent"
    assert len(first.delivery_outcomes[0]["recipient_id"]) == 64

    second = dispatch_monthly_report(
        db, report, settings=settings,
        email_sender=lambda *args: deliveries.append(args),
    )
    assert second.id == first.id
    assert len(deliveries) == 1
    db.expire_all()
    persisted = db.get(MonthlyReportRecord, report.id)
    assert persisted.status == "sent"
    assert persisted.delivery_outcomes[0]["status"] == "sent"


def test_failed_or_unconfigured_delivery_is_recorded_and_can_retry(db):
    client, _ = fake_llm()
    report = prepare_monthly_report(db, 2026, 9, llm_client=client, model="test-model")
    failed = dispatch_monthly_report(db, report, settings=NotificationSettings())
    assert failed.status == "failed"
    assert failed.sent_at is None
    assert failed.delivery_outcomes == [
        {"channel": "email", "status": "skipped", "reason": "not_configured"}
    ]

    settings = NotificationSettings(
        smtp_host="smtp.example", smtp_from="reports@example.org",
        admin_emails=("admin@example.org",),
    )

    def broken_sender(*_args):
        raise TimeoutError("secret SMTP details")

    failed = dispatch_monthly_report(db, report, settings=settings, email_sender=broken_sender)
    assert failed.status == "failed"
    assert failed.delivery_outcomes[0]["status"] == "failed"
    assert failed.delivery_outcomes[0]["error_type"] == "TimeoutError"
    assert "secret SMTP details" not in repr(failed.delivery_outcomes)

    sent = dispatch_monthly_report(db, report, settings=settings, email_sender=lambda *_: None)
    assert sent.status == "sent"
    assert sent.sent_at is not None


def test_partial_delivery_retries_only_unsent_administrators(db):
    client, _ = fake_llm()
    report = prepare_monthly_report(db, 2026, 9, llm_client=client, model="test-model")
    settings = NotificationSettings(
        smtp_host="smtp.example", smtp_from="reports@example.org",
        admin_emails=("first@example.org", "second@example.org", "first@example.org"),
    )
    deliveries = []

    def partial_sender(recipients, *_):
        deliveries.append(recipients)
        if recipients == ("second@example.org",):
            raise TimeoutError("recipient temporarily unreachable")

    first = dispatch_monthly_report(db, report, settings=settings, email_sender=partial_sender)
    assert first.status == "failed"
    assert [entry["status"] for entry in first.delivery_outcomes] == ["sent", "failed"]
    assert "example.org" not in repr(first.delivery_outcomes)
    db.expire_all()

    # A temporary missing configuration must not erase a successful handoff.
    unavailable = dispatch_monthly_report(db, report, settings=NotificationSettings())
    assert unavailable.status == "failed"
    assert unavailable.delivery_outcomes[0]["status"] == "sent"
    assert unavailable.delivery_outcomes[1]["status"] == "skipped"

    second = dispatch_monthly_report(
        db, report, settings=settings, email_sender=lambda recipients, *_: deliveries.append(recipients),
    )
    assert second.status == "sent"
    assert deliveries == [("first@example.org",), ("second@example.org",), ("second@example.org",)]
    assert all(item["status"] == "sent" for item in second.delivery_outcomes)


def test_dispatch_refreshes_stale_status_before_sending(db):
    """A long-lived session must notice that another worker already sent it."""
    client, _ = fake_llm()
    report = prepare_monthly_report(db, 2026, 9, llm_client=client, model="test-model")
    with Session(db.get_bind()) as other:
        saved = other.get(MonthlyReportRecord, report.id)
        saved.status = "sent"
        saved.sent_at = datetime.now(timezone.utc)
        other.commit()
    assert report.status == "draft"
    deliveries = []
    result = dispatch_monthly_report(
        db, report,
        settings=NotificationSettings(
            smtp_host="smtp.example", smtp_from="reports@example.org", admin_emails=("admin@example.org",),
        ),
        email_sender=lambda *args: deliveries.append(args),
    )
    assert result.status == "sent"
    assert deliveries == []
