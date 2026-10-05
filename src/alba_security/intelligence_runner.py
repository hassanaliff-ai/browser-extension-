"""Run daily to prepare each previous closed UTC week/month once. Never mails a draft."""
import argparse
import os
from datetime import timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import alba_security.api  # Register all models and existing migration compatibility.
from alba_security.models import utc_now
from alba_security.intelligence import PeriodRequest, prepare_period_report
from alba_security.schema import ensure_schema


def completed_periods(now=None):
    current = now or utc_now()
    monday = current.date()-timedelta(days=current.weekday())
    month = current.date().replace(day=1)-timedelta(days=1)
    return [('weekly',(monday-timedelta(days=7)).isoformat()),('monthly',month.strftime('%Y-%m'))]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language',choices=['en','ar'],default='en')
    parser.add_argument('--kind',choices=['weekly','monthly','both'],default='both')
    args=parser.parse_args()
    load_dotenv()
    database=os.getenv('DATABASE_URL')
    if not database:
        raise SystemExit('DATABASE_URL is required')
    engine=create_engine(database,pool_pre_ping=True)
    try:
        ensure_schema(engine)
        with Session(engine) as db:
            for kind,period in completed_periods():
                if args.kind in {kind,'both'}:
                    record=prepare_period_report(db,PeriodRequest(kind=kind,period=period,language=args.language))
                    print(f'{record.kind} {record.period}: saved review draft {record.id}')
    finally:
        engine.dispose()


if __name__=='__main__':
    main()
