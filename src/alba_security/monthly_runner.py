"""Schedulable runner for the previous completed UTC month's report."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

# Register every table before creating schema on a fresh deployment.
import alba_security.admin_auth  # noqa: F401
import alba_security.file_lookup  # noqa: F401
import alba_security.overrides  # noqa: F401
from alba_security.models import Base
from alba_security.report_job import dispatch_monthly_report, prepare_monthly_report
from alba_security.reports import _month_bounds
from alba_security.schema import ensure_schema


def completed_report_period(
    year: int | None, month: int | None, *, now: datetime | None = None,
) -> tuple[int, int]:
    """Choose a closed month from one clock reading, including January rollover."""
    if (year is None) != (month is None):
        raise ValueError("--year and --month must be given together")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("The report clock must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if year is None:
        last_month = current.replace(day=1) - timedelta(days=1)
        year, month = last_month.year, last_month.month
    _month_bounds(year, month)
    if (year, month) >= (current.year, current.month):
        raise ValueError("Choose a completed UTC month")
    return year, month


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--year", type=int)
    parser.add_argument("--month", type=int)
    parser.add_argument("--prepare-only", action="store_true", help="Save the report without emailing it")
    args = parser.parse_args()
    try:
        year, month = completed_report_period(args.year, args.month)
    except ValueError as error:
        parser.error(str(error))

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL is required")
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        ensure_schema(engine)
        with Session(engine, expire_on_commit=False) as db:
            report = prepare_monthly_report(db, year, month)
            if not args.prepare_only:
                report = dispatch_monthly_report(db, report)
            print(f"{report.period}: {report.status}")
            for outcome in report.delivery_outcomes:
                print(f"  {outcome['channel']}: {outcome['status']}")
            if not args.prepare_only and report.status != "sent":
                raise SystemExit(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
