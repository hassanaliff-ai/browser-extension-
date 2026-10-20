"""Database operator integration: unique disposable public-schema databases only."""
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import replace
import json, os, shutil
import pytest
from sqlalchemy import create_engine, select, func, text
from sqlalchemy.orm import Session
from sqlalchemy.exc import DBAPIError
from sqlalchemy.engine import make_url
from alba_security.database_migration import load_metadata
from alba_security.schema import ensure_schema
from alba_security.models import Device,Domain
from alba_security.governance import initialize_governance
from alba_security.dbops.common import disposable_database
from alba_security.dbops.backup import create_backup,verify_restore
from alba_security.dbops.migrations import apply_migrations,rollback_test_migration,migration_files
from alba_security.dbops.benchmark import benchmark

MIGRATIONS=Path(__file__).resolve().parents[2]/'sql/migrations'


@pytest.fixture
def operator_database():
    value=os.getenv('EXTSECURE_TEST_DATABASE_URL'); admin=os.getenv('EXTSECURE_TEST_ADMIN_JSON')
    if not value or not admin: pytest.skip('Dedicated database and local test administrator required')
    owner=make_url(value)
    assert owner.database.startswith('extsecure_test_')
    kwargs=json.loads(admin)
    with disposable_database(kwargs,owner,'operations') as target:
        engine=create_engine(target);load_metadata();ensure_schema(engine)
        with Session(engine) as db:
            initialize_governance(db);db.add(Device(id='test',name='Before backup'));db.commit()
        yield engine,target,kwargs
        engine.dispose()


def test_backup_restore_verifies_snapshot_even_after_source_changes(operator_database,tmp_path):
    engine,url,admin=operator_database
    result=create_backup(tmp_path,url)
    with Session(engine) as db: db.get(Device,'test').name='Changed after backup';db.commit()
    restored=verify_restore(tmp_path,result['backup_file'],admin,url)
    assert restored['verified'] and restored['tables']==len(load_metadata().tables) and restored['disposable_database_removed']
    with Session(engine) as db: assert db.get(Device,'test').name=='Changed after backup'


def test_backup_tampering_fails_before_restore_connection(operator_database,tmp_path,monkeypatch):
    _,url,admin=operator_database
    result=create_backup(tmp_path,url); path=Path(result['backup_file'])
    with path.open('ab') as stream: stream.write(b'tampered')
    import alba_security.dbops.backup as module
    monkeypatch.setattr(module,'disposable_database',lambda *args:pytest.fail('A database must not be created for a corrupt backup'))
    with pytest.raises(ValueError,match='checksum'): verify_restore(tmp_path,path,admin,url)


def test_migrations_are_idempotent_readonly_to_runtime_and_test_rollback_works(operator_database):
    engine,url,_=operator_database
    role=make_url(os.environ['EXTSECURE_TEST_RUNTIME_URL']).username
    first=apply_migrations(engine,MIGRATIONS,runtime_role=role)
    versions=[item['version'] for item in migration_files(MIGRATIONS)]
    assert first['applied_now']==versions
    assert apply_migrations(engine,MIGRATIONS)['applied_now']==[]
    with engine.connect() as db:
        assert not db.scalar(text("SELECT has_table_privilege(:role,'extsecure_schema_migrations','UPDATE')"),{'role':role})
    assert rollback_test_migration(engine,MIGRATIONS)=={'rolled_back':versions[-1]}
    assert apply_migrations(engine,MIGRATIONS)['applied_now']==[versions[-1]]
    production=create_engine(url.set(database='extsecure'))
    try:
        with pytest.raises(ValueError):rollback_test_migration(production,MIGRATIONS)
    finally:production.dispose()




def test_failed_migration_rolls_back_ddl_and_ledger(operator_database,tmp_path):
    engine,_,_=operator_database
    shutil.copytree(MIGRATIONS,tmp_path/'migrations');folder=tmp_path/'migrations';apply_migrations(engine,folder)
    next_version=f"{int(migration_files(folder)[-1]['version'])+1:04d}"
    (folder/(next_version+'_failure.sql')).write_text('-- migrate:up\nCREATE TABLE rollback_probe(id INT); SELECT 1/0;\n-- migrate:down\nDROP TABLE rollback_probe;\n')
    with pytest.raises(DBAPIError):apply_migrations(engine,folder)
    with engine.connect() as db:
        assert db.scalar(text("SELECT to_regclass('public.rollback_probe')")) is None
        assert db.scalar(text('SELECT count(*) FROM extsecure_schema_migrations'))==len(migration_files(MIGRATIONS))






def test_benchmark_uses_synthetic_data_and_measures_plans(operator_database):
    _,url,admin=operator_database
    result=benchmark(admin,url,rows=1000)
    assert result['synthetic_scans']==1000 and result['disposable_database_removed']
    assert set(result['measurements'])=={'device_history','report_totals','domain_ranking'}
    assert all(value['median_ms']>=0 for value in result['measurements'].values())


def test_retired_email_metadata_is_removed_without_losing_reports(operator_database):
    from alba_security.report_job import MonthlyReportRecord
    from alba_security.models import SecurityEvent,Scan
    from sqlalchemy import inspect
    engine,_,_=operator_database
    with Session(engine) as db:
        report=MonthlyReportRecord(period='2026-09',stats={'total_scans':1},subject='Saved report',body='Retained body',summary_source='local')
        db.add(report)
        scan=Scan(device_id='test',target_kind='hash',target_fingerprint='a'*64,target_display='fixture',signals=[],score=80,severity='High',completeness='complete')
        db.add(scan);db.flush()
        db.add_all([SecurityEvent(event_type='notification_delivery',severity='High',scan_id=scan.id,device_id='test',message='Legacy notice',details={'channel':'email'}),
                    SecurityEvent(event_type='notification_delivery',severity='High',scan_id=scan.id,device_id='test',message='Retained notice',details={'channel':'webhook'})])
        db.commit()
    with engine.begin() as db:
        db.exec_driver_sql('ALTER TABLE monthly_reports ADD COLUMN sent_at TIMESTAMP WITH TIME ZONE')
        db.exec_driver_sql("ALTER TABLE monthly_reports ADD COLUMN delivery_outcomes JSON NOT NULL DEFAULT '[]'")
    apply_migrations(engine,MIGRATIONS)
    assert not {'sent_at','delivery_outcomes'} & {c['name'] for c in inspect(engine).get_columns('monthly_reports')}
    with Session(engine) as db:
        assert db.query(MonthlyReportRecord).one().body=='Retained body'
        events=db.query(SecurityEvent).all()
        assert len(events)==1 and events[0].details['channel']=='webhook'
