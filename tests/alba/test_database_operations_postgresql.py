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
from alba_security.dbops.migrations import apply_migrations,rollback_test_migration
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
    assert first['applied_now']==['0001','0002','0003','0004']
    assert apply_migrations(engine,MIGRATIONS)['applied_now']==[]
    with engine.connect() as db:
        assert not db.scalar(text("SELECT has_table_privilege(:role,'extsecure_schema_migrations','UPDATE')"),{'role':role})
    assert rollback_test_migration(engine,MIGRATIONS)=={'rolled_back':'0004'}
    assert apply_migrations(engine,MIGRATIONS)['applied_now']==['0004']
    production=create_engine(url.set(database='extsecure'))
    try:
        with pytest.raises(ValueError):rollback_test_migration(production,MIGRATIONS)
    finally:production.dispose()




def test_failed_migration_rolls_back_ddl_and_ledger(operator_database,tmp_path):
    engine,_,_=operator_database
    shutil.copytree(MIGRATIONS,tmp_path/'migrations');folder=tmp_path/'migrations';apply_migrations(engine,folder)
    (folder/'0005_failure.sql').write_text('-- migrate:up\nCREATE TABLE rollback_probe(id INT); SELECT 1/0;\n-- migrate:down\nDROP TABLE rollback_probe;\n')
    with pytest.raises(DBAPIError):apply_migrations(engine,folder)
    with engine.connect() as db:
        assert db.scalar(text("SELECT to_regclass('public.rollback_probe')")) is None
        assert db.scalar(text('SELECT count(*) FROM extsecure_schema_migrations'))==4






def test_benchmark_uses_synthetic_data_and_measures_plans(operator_database):
    _,url,admin=operator_database
    result=benchmark(admin,url,rows=1000)
    assert result['synthetic_scans']==1000 and result['disposable_database_removed']
    assert set(result['measurements'])=={'device_history','report_totals','domain_ranking'}
    assert all(value['median_ms']>=0 for value in result['measurements'].values())
