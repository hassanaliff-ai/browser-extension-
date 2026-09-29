"""Durable monthly report preparation and administrator delivery."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, JSON, String, Text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.models import Base, new_id, utc_now
from alba_security.notifications import EmailSender, NotificationSettings, send_monthly_report
from alba_security.reports import generate_monthly_report


class MonthlyReportRecord(Base):
    """One generated summary per UTC calendar month."""

    __tablename__ = "monthly_reports"
    __table_args__ = (
        CheckConstraint("status IN ('draft', 'sent', 'failed')", name="ck_monthly_report_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    period: Mapped[str] = mapped_column(String(7), unique=True, nullable=False, index=True)
    stats: Mapped[dict] = mapped_column(JSON, nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    summary_source: Mapped[str] = mapped_column(String(30), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_outcomes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(12), default="draft", nullable=False)


def prepare_monthly_report(
    db: Session,
    year: int,
    month: int,
    *,
    llm_client: Any | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> MonthlyReportRecord:
    """Generate and save a report once; return an existing report unchanged.

    A unique period constraint is the final guard if two workers prepare the
    same month concurrently. The API must import this module before create_all.
    """
    if not 2000 <= year <= 2100 or not 1 <= month <= 12:
        raise ValueError("year must be 2000–2100 and month must be 1–12")
    period = f"{year:04d}-{month:02d}"
    existing = db.scalar(select(MonthlyReportRecord).where(MonthlyReportRecord.period == period))
    if existing is not None:
        return existing

    generated = generate_monthly_report(
        db, year, month, llm_client=llm_client, api_key=api_key, model=model
    )
    record = MonthlyReportRecord(
        period=period,
        stats=generated["stats"],
        subject=generated["subject"],
        body=generated["body"],
        summary_source=generated["summary_source"],
        generated_at=utc_now(),
        delivery_outcomes=[],
        status="draft",
    )
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Another worker may have won the unique-period race.
        existing = db.scalar(select(MonthlyReportRecord).where(MonthlyReportRecord.period == period))
        if existing is None:
            raise
        return existing
    return record


def dispatch_monthly_report(
    db: Session,
    record: MonthlyReportRecord,
    *,
    settings: NotificationSettings | None = None,
    email_sender: EmailSender | None = None,
) -> MonthlyReportRecord:
    """Send a saved report, record outcomes, and skip an already sent period.

    On PostgreSQL, FOR UPDATE serializes concurrent dispatches. As with most
    external sends, a process crash between SMTP acceptance and the database
    commit can still cause a retry; deployments should run one report worker.
    """
    report = db.scalar(
        select(MonthlyReportRecord)
        .where(MonthlyReportRecord.id == record.id)
        .with_for_update()
    )
    if report is None:
        raise ValueError("Monthly report is not stored")
    if report.status == "sent" and report.sent_at is not None:
        return report

    outcomes = send_monthly_report(
        {"subject": report.subject, "body": report.body},
        settings=settings,
        email_sender=email_sender,
    )
    report.delivery_outcomes = outcomes
    if outcomes and all(item["status"] == "sent" for item in outcomes):
        report.status = "sent"
        report.sent_at = utc_now()
    else:
        report.status = "failed"
        report.sent_at = None
    db.commit()
    return report
