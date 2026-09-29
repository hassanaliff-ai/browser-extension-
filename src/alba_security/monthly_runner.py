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
from alba_security.schema import ensure_schema


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--year", type=int)
    parser.add_argument("--month", type=int)
    parser.add_argument("--prepare-only", action="store_true", help="Save the report without emailing it")
    args = parser.parse_args()
    if (args.year is None) != (args.month is None):
        parser.error("--year and --month must be given together")
    last_month = datetime.now(timezone.utc).replace(day=1) - timedelta(days=1)
    year, month = (args.year, args.month) if args.year is not None else (last_month.year, last_month.month)
    current = datetime.now(timezone.utc)
    if (year, month) >= (current.year, current.month):
        parser.error("Choose a completed UTC month")

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL is required")
    engine = create_engine(database_url, pool_pre_ping=True)
    ensure_schema(engine)
    with Session(engine, expire_on_commit=False) as db:
        report = prepare_monthly_report(db, year, month)
        if not args.prepare_only:
            report = dispatch_monthly_report(db, report)
        print(f"{report.period}: {report.status}")
        for outcome in report.delivery_outcomes:
            print(f"  {outcome['channel']}: {outcome['status']}")


if __name__ == "__main__":
    main()
