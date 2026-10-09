"""Real PostgreSQL tests, restricted to a dedicated extsecure_test_* database."""
import os,uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine,select,text,func
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError,ProgrammingError
from sqlalchemy.orm import Session
from alba_security.database_migration import load_metadata,migrate_snapshot
from alba_security.database_queries import record_domain,scan_history_query,scan_statistics_query
from alba_security.models import Device,Domain,Scan
from alba_security.schema import ensure_schema
from tests.alba.test_governance import system,scan


@pytest.fixture
def pg_engine():
    value=os.getenv('EXTSECURE_TEST_DATABASE_URL')
    if not value:pytest.skip('Set a dedicated PostgreSQL test database URL')
    url=make_url(value)
    if url.get_backend_name()!='postgresql' or not url.database.startswith('extsecure_test_'):
        raise ValueError('Refusing to run integration tests on a non-test database')
    namespace='extsecure_test_'+uuid.uuid4().hex
    owner=create_engine(url,pool_pre_ping=True)
    with owner.begin() as db:db.exec_driver_sql('CREATE SCHEMA '+namespace)
    engine=create_engine(url,connect_args={'options':'-c timezone=UTC -c search_path='+namespace})
    load_metadata();ensure_schema(engine)
    yield engine,namespace,url
    engine.dispose()
    with owner.begin() as db:db.exec_driver_sql('DROP SCHEMA '+namespace+' CASCADE')
    owner.dispose()


def seed(db,now):
    db.add(Device(id='isolated-device',name='Isolated PostgreSQL device'));db.flush()
    domain=record_domain(db,'https://example.com/private?secret=NEVER-PERSIST',now)
    db.add(Scan(device_id='isolated-device',domain_id=domain,target_kind='url',target_fingerprint='a'*64,
        target_display='https://example.com/',signals=[{'code':'malicious_url','status':'clear'}],score=0,
        severity='Low',completeness='complete',risk_policy_version='test-policy',created_at=now))


def test_postgresql_foreign_keys_and_risk_constraints_reject_invalid_writes(pg_engine):
    engine,_,_=pg_engine
    with Session(engine) as db:
        now=datetime(2026,10,9,tzinfo=timezone.utc);seed(db,now);db.commit()
        for change in [{'device_id':'absent'},{'domain_id':'absent'},{'score':101},{'severity':'Safe'},{'completeness':'fake'}]:
            with pytest.raises(IntegrityError),db.begin_nested():
                values=dict(device_id='isolated-device',target_kind='url',target_fingerprint='b'*64,
                    target_display='https://example.com/',signals=[],score=0,severity='Low',completeness='complete',created_at=now)
                db.add(Scan(**(values|change)));db.flush()
        assert db.scalar(select(func.count()).select_from(Scan))==1


def test_concurrent_domain_upserts_have_one_identity_and_stable_times(pg_engine):
    engine,_,_=pg_engine
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    def insert(offset):
        with Session(engine) as db:
            identity=record_domain(db,'https://EXAMPLE.com/path?private=value',now+timedelta(seconds=offset));db.commit();return identity
    with ThreadPoolExecutor(max_workers=2) as pool:identities=list(pool.map(insert,[1,0]))
    assert len(set(identities))==1
    with Session(engine) as db:
        row=db.get(Domain,identities[0]);assert row.first_seen==now and row.last_seen==now+timedelta(seconds=1)
        assert db.scalar(select(func.count()).select_from(Domain))==1


def test_postgresql_history_risk_and_utc_reporting_views(pg_engine):
    engine,_,_=pg_engine
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    with Session(engine) as db:
        seed(db,now);db.commit()
        assert len(db.execute(scan_history_query(now,now+timedelta(days=1))).all())==1
        assert db.execute(scan_statistics_query(now,now+timedelta(days=1))).mappings().one()['unique_domains']==1
        assert db.execute(text('SELECT score,risk_policy_version FROM extsecure_risk_results')).one()==(0,'test-policy')
        for period in ('daily','weekly','monthly'):
            row=db.execute(text('SELECT total_scans,high_risk_scans,unknown_scans FROM extsecure_'+period+'_statistics')).one()
            assert row==(1,0,0)


def test_postgresql_transaction_rolls_back_domain_and_scan_together(pg_engine):
    engine,_,_=pg_engine
    with Session(engine) as db:
        seed(db,datetime(2026,10,9,tzinfo=timezone.utc));db.flush();db.rollback()
        for table in (Device,Domain,Scan):assert db.scalar(select(func.count()).select_from(table))==0


def test_verified_migration_preserves_authentication_and_extension_api_queries(pg_engine,system):
    engine,namespace,url=pg_engine
    source_client,source_app,headers,_=system
    result=scan(source_client)
    counts=migrate_snapshot(source_app.state.engine,engine)
    assert counts['scans']==1 and counts['domains']==1 and counts['admin_sessions']>=2
    from alba_security.api import create_app
    directory=source_app.state.admin_directory
    test_url=url.update_query_dict({'options':'-c timezone=UTC -c search_path='+namespace})
    app=create_app(database_url=test_url.render_as_string(hide_password=False),
        admin_auth=directory.primary,additional_admins=[a for name,a in directory.accounts.items() if name!=directory.primary.username],
        ingest_token='isolated-postgres-ingest',alert_notifier=lambda **_:[])
    with TestClient(app) as client:
        response=client.get('/api/scans',headers=headers['hasan'])
        assert response.status_code==200 and response.json()[0]['id']==result['id']
        assert client.get('/api/overview',headers=headers['hasan']).status_code==200
        assert client.get('/api/scans').status_code==401
    app.state.engine.dispose()
    with pytest.raises(ValueError,match='Destination must be empty'):
        migrate_snapshot(source_app.state.engine,engine)


def test_failed_verification_rolls_back_the_entire_import(pg_engine,system,monkeypatch):
    engine,_,_=pg_engine
    source_client,source_app,_,_=system
    scan(source_client)
    import alba_security.database_migration as migration
    original=migration.table_digest
    def mismatch(connection,table):
        result=original(connection,table)
        return (result[0],'forced-isolated-test-mismatch') if connection.dialect.name=='postgresql' and table.name=='scans' else result
    monkeypatch.setattr(migration,'table_digest',mismatch)
    with pytest.raises(ValueError,match='verification failed'):
        migrate_snapshot(source_app.state.engine,engine)
    with engine.connect() as db:
        for table in load_metadata().tables.values():assert db.scalar(select(func.count()).select_from(table))==0


def test_runtime_can_startup_and_append_audit_but_cannot_change_schema_or_history(pg_engine):
    engine,namespace,url=pg_engine
    runtime_value=os.getenv('EXTSECURE_TEST_RUNTIME_URL')
    if not runtime_value:pytest.skip('A dedicated runtime test URL is required')
    runtime_url=make_url(runtime_value)
    assert runtime_url.database==url.database and runtime_url.database.startswith('extsecure_test_')
    role=engine.dialect.identifier_preparer.quote(runtime_url.username)
    with engine.begin() as db:
        db.exec_driver_sql(f'GRANT USAGE ON SCHEMA {namespace} TO {role}')
        db.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {namespace} TO {role}')
        db.exec_driver_sql(f'REVOKE UPDATE,DELETE,TRUNCATE ON TABLE {namespace}.governance_audit FROM {role}')
    runtime=create_engine(runtime_url,connect_args={'options':'-c timezone=UTC -c search_path='+namespace})
    try:
        ensure_schema(runtime)
        from alba_security.governance import audit,GovernanceAudit
        with Session(runtime) as db:
            audit(db,'database','isolated-test','test-actor','verified',test=True);db.commit()
            assert db.scalar(select(func.count()).select_from(GovernanceAudit))==1
            assert db.execute(text('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user')).one()==(False,False,False)
            for command in ['UPDATE governance_audit SET actor=\'changed\'','DELETE FROM governance_audit','CREATE TABLE unsafe_schema_change(id int)']:
                with pytest.raises(ProgrammingError),db.begin_nested():db.execute(text(command))
            assert db.scalar(select(func.count()).select_from(GovernanceAudit))==1
    finally:runtime.dispose()
