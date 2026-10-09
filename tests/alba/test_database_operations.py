from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import pytest
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from alba_security.models import Domain
from alba_security.governance import GovernanceState, GovernanceAudit, initialize_governance
from alba_security.dbops.transfer import import_domains, export_records, validate_domain_row
from alba_security.dbops.monitoring import Thresholds, evaluate
from alba_security.dbops.common import private_path
from alba_security.dbops.migrations import migration_files
from tests.alba.test_database_queries import engine

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)


def row(host='example.com'):
    return {'hostname': host, 'first_seen': NOW.isoformat(), 'last_seen': (NOW + timedelta(days=1)).isoformat()}


def seed_policy(engine):
    with Session(engine) as db: initialize_governance(db)


@pytest.mark.parametrize('change', [{'password':'secret'}, {'score':90}, {'hostname':'https://example.com/path'},
    {'hostname':'example.com:443'}, {'hostname':'user@example.com'}, {'hostname':'[::1]/private'},
    {'first_seen':'2026-10-09'}, {'last_seen':'2026-10-08T00:00:00Z'}, {'hostname':'=SUM(A1)'}, {'hostname':'example.com?secret=x'}])
def test_import_rejects_unapproved_fields_urls_credentials_and_bad_times(change):
    with pytest.raises(ValueError): validate_domain_row(row() | change)


def test_import_dry_run_duplicates_merge_commit_and_audit(engine, tmp_path):
    seed_policy(engine)
    path = tmp_path/'input.json'; path.write_text(json.dumps([row(), row('EXAMPLE.com'), row('second.example')]))
    result = import_domains(engine, path)
    assert result['duplicate_rows']==1 and result['new_domains']==2 and not result['committed']
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Domain))==0
        assert db.scalar(select(func.count()).select_from(GovernanceAudit))==0
    assert import_domains(engine, path, commit=True)['committed']
    assert import_domains(engine, path, commit=True)['existing_domains']==2
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Domain))==2
        assert db.scalar(select(func.count()).select_from(GovernanceAudit))==2


def test_invalid_later_row_cannot_partially_import(engine, tmp_path):
    seed_policy(engine)
    path=tmp_path/'bad.json'; path.write_text(json.dumps([row(), row() | {'api_key':'not-allowed'}]))
    with pytest.raises(ValueError): import_domains(engine, path, commit=True)
    with Session(engine) as db: assert db.scalar(select(func.count()).select_from(Domain))==0


def test_csv_roundtrip_export_limits_and_no_overwrite(engine, tmp_path):
    seed_policy(engine)
    path=tmp_path/'input.json'; path.write_text(json.dumps([row(), row('second.example')]))
    import_domains(engine,path,commit=True)
    exported=tmp_path/'domains.csv'
    result=export_records(engine,exported,'domains',NOW,NOW+timedelta(days=2),limit=1)
    assert result['exported_rows']==1 and result['truncated']
    assert import_domains(engine,exported)['existing_domains']==1
    with pytest.raises(FileExistsError): export_records(engine,exported,'domains',NOW,NOW+timedelta(days=2))
    with pytest.raises(ValueError): export_records(engine,tmp_path/'secret.json','admin_sessions',NOW,NOW+timedelta(days=2))


def test_domain_collection_policy_controls_import_and_export(engine, tmp_path):
    seed_policy(engine)
    with Session(engine) as db:
        state=db.get(GovernanceState,'privacy'); state.data={**state.data,'show_hostnames':False}; db.commit()
    path=tmp_path/'input.json'; path.write_text(json.dumps([row()]))
    with pytest.raises(ValueError): import_domains(engine,path,commit=True)
    with pytest.raises(ValueError): export_records(engine,tmp_path/'out.csv','domains',NOW,NOW+timedelta(days=2))


@pytest.mark.parametrize('value', ['../secret.json','../../.env','nested/../../../secret.json'])
def test_private_exchange_paths_cannot_escape(tmp_path,value):
    with pytest.raises(ValueError): private_path(tmp_path,value)


@pytest.mark.parametrize('values',[{'connections_percent':101},{'query_seconds':0},{'database_mb':float('nan')},{'blocked_sessions':0.5},{'database_mb':-1}])
def test_monitor_rejects_invalid_thresholds(values):
    with pytest.raises(ValueError): Thresholds(**values)


def test_monitor_alerts_growth_deadlock_deltas_and_counter_reset():
    metrics={'database_bytes':100*1024**2,'connections_percent':10,'blocked_sessions':0,
        'long_queries':0,'long_transactions':0,'deadlocks':1,'captured_at':NOW.isoformat()}
    assert evaluate(metrics,Thresholds())['status']=='healthy'
    previous=metrics | {'database_bytes':99*1024**2,'deadlocks':0,'captured_at':(NOW-timedelta(minutes=5)).isoformat()}
    alerts=evaluate(metrics,Thresholds(),previous)['alerts']
    assert {a['code'] for a in alerts}=={'database_growth','new_deadlocks'}
    assert not any(a['code']=='new_deadlocks' for a in evaluate(metrics|{'deadlocks':0},Thresholds(),previous|{'deadlocks':5})['alerts'])


def test_migration_names_versions_sections_and_portable_newline_checksums(tmp_path):
    first=tmp_path/'0001_first.sql'; first.write_bytes(b'-- migrate:up\nSELECT 1;\n-- migrate:down\nSELECT 1;\n')
    digest=migration_files(tmp_path)[0]['checksum']
    first.write_bytes(first.read_bytes().replace(b'\n',b'\r\n'))
    assert migration_files(tmp_path)[0]['checksum']==digest
    (tmp_path/'0001_second.sql').write_text('-- migrate:up\nSELECT 1;\n-- migrate:down\nSELECT 1;\n')
    with pytest.raises(ValueError): migration_files(tmp_path)
