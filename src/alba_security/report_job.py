"""Durable monthly report preparation for in-extension review."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, JSON, String, Text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.models import Base, new_id, utc_now
from alba_security.reports import _month_bounds, generate_monthly_report


class MonthlyReportRecord(Base):
    """One generated summary per UTC calendar month."""

    __tablename__ = "monthly_reports"
    __table_args__ = (
        CheckConstraint("status IN ('draft')", name="ck_monthly_report_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    period: Mapped[str] = mapped_column(String(7), unique=True, nullable=False, index=True)
    stats: Mapped[dict] = mapped_column(JSON, nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    summary_source: Mapped[str] = mapped_column(String(30), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
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
    _month_bounds(year, month)
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
