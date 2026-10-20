"""Durable monthly report generation tests."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import alba_security.overrides  # noqa: F401 — register override table before create_all
from alba_security.models import Base, Device, Scan
from alba_security.report_job import (
    MonthlyReportRecord,
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
    assert not hasattr(first, "sent_at")
    assert not hasattr(first, "delivery_outcomes")
