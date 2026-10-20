"""Apply the explicitly requested email-only database cleanup after a backup."""
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'scripts'),str(ROOT/'src')]
from sqlalchemy import create_engine, text, inspect
from setup_postgresql import stored_urls
from alba_security.dbops.migrations import apply_migrations
from alba_security.database_health import database_status


def snapshot(db):
    tables=inspect(db).get_table_names()
    # Compare all retained records; delivery metadata alone is excluded.
    retained={}
    for table in tables:
        if table=='extsecure_schema_migrations': continue
        if table=='monthly_reports':
            sql='SELECT id,period,stats,subject,body,summary_source,generated_at FROM monthly_reports ORDER BY id'
        elif table=='security_events':
            sql="SELECT * FROM security_events WHERE NOT (event_type='notification_delivery' AND COALESCE(details->>'channel','')='email') ORDER BY id"
        else:
            quoted=db.dialect.identifier_preparer.quote(table)
            sql='SELECT * FROM '+quoted+' ORDER BY 1'
        retained[table]=[dict(row) for row in db.execute(text(sql)).mappings()]
    return json.dumps(retained,sort_keys=True,default=str)


def main():
    owner,app=stored_urls()
    engine=create_engine(owner,pool_pre_ping=True)
    try:
        with engine.connect() as db:
            before=snapshot(db)
            email_events=db.scalar(text("SELECT count(*) FROM security_events WHERE event_type='notification_delivery' AND details->>'channel'='email'"))
            reports=db.scalar(text('SELECT count(*) FROM monthly_reports'))
        result=apply_migrations(engine,ROOT/'sql/migrations',runtime_role=app.username)
        with engine.connect() as db:
            if snapshot(db)!=before: raise RuntimeError('Retained evidence changed unexpectedly')
            columns={c['name'] for c in inspect(db).get_columns('monthly_reports')}
            if columns & {'sent_at','delivery_outcomes'}: raise RuntimeError('Delivery columns remain')
            remaining=db.scalar(text("SELECT count(*) FROM security_events WHERE event_type='notification_delivery' AND details->>'channel'='email'"))
        runtime=create_engine(app,pool_pre_ping=True)
        try: health=database_status(runtime)
        finally: runtime.dispose()
        if not health['healthy']: raise RuntimeError('Database health check failed')
        summary={**result,'retained_records_verified':True,'saved_monthly_reports_preserved':reports,
                 'email_notification_events_removed':email_events,'email_notification_events_remaining':remaining,
                 'email_delivery_columns_removed':True,'database_healthy':True,'table_count':health['table_count'],
                 'view_count':health['view_count']}
        path=ROOT/'.private/email-removal-verification.json'
        path.write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(json.dumps(summary))
    finally: engine.dispose()


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('Email metadata cleanup did not complete ('+type(error).__name__+'). Check the private backup and migration state.',file=sys.stderr)
        raise SystemExit(1)
