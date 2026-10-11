"""Native scheduled task entry point; no credentials or model content in logs."""
from pathlib import Path
import argparse,json,os,sys
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import alba_security.api
from alba_security.automatic_reports import generate_scheduled_report,scheduled_period

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind',required=True,choices=['weekly','monthly'])
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    load_dotenv(ROOT/'.env',override=False)
    if args.dry_run:
        payload,bounds=scheduled_period(args.kind)
        print(json.dumps({'kind':args.kind,'period':payload.period,'window_utc':[v.isoformat() for v in bounds] if bounds else 'Previous completed UTC month','writes':False}))
        return 0
    log=ROOT/'.private/automatic-reports.jsonl';log.parent.mkdir(exist_ok=True)
    entry={'at':datetime.now(timezone.utc).isoformat(),'kind':args.kind}
    engine=None
    try:
        import start_extsecure
        if start_extsecure.main()!=0:
            raise RuntimeError('Local services could not start')
        engine=create_engine(os.environ['DATABASE_URL'],pool_pre_ping=True,
            connect_args={'application_name':'ExtSecure Report Scheduler'})
        with Session(engine,expire_on_commit=False) as db:
            record,created=generate_scheduled_report(db,args.kind,language=os.getenv('REPORT_LANGUAGE','en'))
            entry.update(status='generated' if created else 'already_saved',report_id=record.id,period=record.period)
        result=0
    except Exception as error:
        entry.update(status='failed',error_type=type(error).__name__)
        result=1
    finally:
        if engine:engine.dispose()
        with log.open('a',encoding='utf-8') as target:target.write(json.dumps(entry)+'\n')
    if sys.stdout:print(json.dumps(entry))
    return result

if __name__=='__main__':
    raise SystemExit(main())
