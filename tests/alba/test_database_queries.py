from datetime import datetime,timedelta,timezone
import pytest
from sqlalchemy import create_engine,event,select,func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.dialects import postgresql
from alba_security.database_migration import load_metadata,table_digest
from alba_security.database_queries import canonical_hostname,record_domain,scan_history_query,scan_statistics_query,ScanCursor,scan_history_page,report_totals_query,domain_risk_query
from alba_security.models import Device,Domain,Scan,Finding,Alert,SecurityEvent,Extension
from tests.alba.test_governance import system,scan


@pytest.mark.parametrize('value,expected',[
 ('https://EXAMPLE.com:443/private?token=DO-NOT-STORE#secret','example.com'),
 ('https://faß.de/path','xn--fa-hia.de'),('https://example.com./','example.com'),
 ('https://[::1]/','::1'),('file:///private.txt',None),('https://user:pass@example.com/',None)])
def test_hostnames_are_canonical_and_private_url_parts_are_not_retained(value,expected):
    assert canonical_hostname(value)==expected


@pytest.fixture
def engine(tmp_path):
    load_metadata()
    result=create_engine('sqlite:///'+str(tmp_path/'isolated.sqlite'))
    @event.listens_for(result,'connect')
    def foreign_keys(connection,_):connection.execute('PRAGMA foreign_keys=ON')
    from alba_security.schema import ensure_schema
    ensure_schema(result)
    yield result
    result.dispose()


def test_domain_upsert_reuses_identity_preserves_first_and_last_times_and_rolls_back(engine):
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    with Session(engine) as db:
        original=record_domain(db,'https://example.com/?private=x',now)
        assert record_domain(db,'https://EXAMPLE.COM/path',now+timedelta(days=1))==original
        assert record_domain(db,'https://example.com/',now-timedelta(days=1))==original
        db.commit()
        row=db.get(Domain,original)
        assert row.first_seen.replace(tzinfo=timezone.utc)==now-timedelta(days=1)
        assert row.last_seen.replace(tzinfo=timezone.utc)==now+timedelta(days=1)
        record_domain(db,'https://rollback.example/',now);db.rollback()
        assert db.scalar(select(func.count()).select_from(Domain))==1


def test_history_and_statistics_use_half_open_utc_windows_and_parameter_binding(engine):
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    with Session(engine) as db:
        db.add(Device(id='lab',name='Lab'));db.flush()
        for offset,severity,score in [(0,'Low',0),(1,'Unknown',None),(2,'High',70)]:
            db.add(Scan(device_id='lab',target_kind='url',target_fingerprint='a'*64,target_display='https://example.com',
                signals=[],score=score,severity=severity,completeness='unknown' if score is None else 'complete',created_at=now+timedelta(days=offset)))
        db.commit()
        end=now+timedelta(days=2)
        totals=db.execute(scan_statistics_query(now,end)).mappings().one()
        assert totals['total_scans']==2 and totals['unknown_scans']==1 and totals['high_risk_scans']==0
        assert len(db.execute(scan_history_query(now,end,device_id='lab')).all())==2
        assert db.execute(scan_history_query(now,end,device_id="lab' OR 1=1 --")).all()==[]
        compiled=scan_history_query(now,end,device_id='sensitive-name').compile(dialect=postgresql.dialect())
        assert 'sensitive-name' not in str(compiled) and 'sensitive-name' in compiled.params.values()
        with pytest.raises(ValueError):scan_history_query(now.replace(tzinfo=None),end)
        with pytest.raises(ValueError):scan_history_query(now,end,limit=501)


@pytest.mark.parametrize('change',[{'score':101},{'score':-1},{'severity':'Safe'},{'completeness':'fake'},{'target_kind':'unknown'}])
def test_database_rejects_invalid_risk_fields(engine,change):
    with Session(engine) as db:
        db.add(Device(id='lab',name='Lab'));db.commit()
        payload=dict(device_id='lab',target_kind='url',target_fingerprint='a'*64,target_display='https://example.com',signals=[],score=0,severity='Low',completeness='complete')
        db.add(Scan(**(payload|change)))
        with pytest.raises(IntegrityError):db.commit()
        db.rollback()
        assert db.scalar(select(func.count()).select_from(Scan))==0


def test_api_records_domain_and_policy_version_in_the_scan_transaction(system):
    client,app,headers,_=system
    result=scan(client)
    with app.state.session_factory() as db:
        row=db.get(Scan,result['id'])
        assert db.get(Domain,row.domain_id).hostname=='private.example'
        assert row.risk_policy_version==result['risk_policy_version']


def test_privacy_disabled_does_not_collect_a_domain_record(system):
    client,app,headers,_=system
    from alba_security.governance import GovernanceState
    with app.state.session_factory() as db:
        settings=db.get(GovernanceState,'privacy');settings.data={**settings.data,'show_hostnames':False};db.commit()
    result=scan(client)
    with app.state.session_factory() as db:
        assert db.get(Scan,result['id']).domain_id is None
        assert db.scalar(select(func.count()).select_from(Domain))==0


def test_keyset_pagination_handles_equal_timestamps_new_rows_and_device_scope(engine):
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    with Session(engine) as db:
        db.add_all([Device(id='lab',name='Lab'),Device(id='other',name='Other')]);db.flush()
        for identity,device in [('a','lab'),('b','lab'),('c','lab'),('z','other')]:
            db.add(Scan(id=identity,device_id=device,target_kind='url',target_fingerprint='a'*64,
                target_display='https://example.com',signals=[],score=0,severity='Low',completeness='complete',created_at=now))
        db.commit()
        first=scan_history_page(db,now,now+timedelta(days=1),device_id='lab',limit=2)
        assert [row['id'] for row in first['items']]==['c','b']
        db.add(Scan(id='d',device_id='lab',target_kind='url',target_fingerprint='a'*64,
            target_display='https://example.com',signals=[],score=0,severity='Low',completeness='complete',created_at=now));db.commit()
        second=scan_history_page(db,now,now+timedelta(days=1),device_id='lab',limit=2,before=first['next_cursor'])
        assert [row['id'] for row in second['items']]==['a'] and second['next_cursor'] is None
        with pytest.raises(ValueError):ScanCursor(now.replace(tzinfo=None),'a')
        with pytest.raises(ValueError):scan_history_page(db,now,now+timedelta(days=1),limit=0)


def test_report_totals_do_not_multiply_child_rows_and_domain_risk_is_scoped(engine):
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    with Session(engine) as db:
        db.add(Device(id='lab',name='Lab'));db.flush()
        host=record_domain(db,'https://example.com/',now)
        db.add(Scan(id='scan',device_id='lab',domain_id=host,target_kind='url',target_fingerprint='a'*64,
            target_display='https://example.com',signals=[],score=90,severity='Critical',completeness='complete',created_at=now));db.flush()
        for _ in range(2):db.add(Finding(scan_id='scan',device_id='lab',signal_code='malicious_url',title='Finding',points=80,severity='High',created_at=now))
        for _ in range(3):db.add(Alert(scan_id='scan',message='Alert',severity='Critical',created_at=now))
        for _ in range(4):db.add(SecurityEvent(scan_id='scan',device_id='lab',event_type='scan_completed',message='Event',severity='Critical',created_at=now))
        db.commit()
        totals=dict(db.execute(report_totals_query(now,now+timedelta(days=1),device_id='lab')).mappings().one())
        assert totals=={'total_scans':1,'findings':2,'alerts':3,'events':4,'high_risk_scans':1,'unknown_scans':0}
        empty=dict(db.execute(report_totals_query(now,now+timedelta(days=1),device_id='other')).mappings().one())
        assert not any(empty.values())
        domain=db.execute(domain_risk_query(now,now+timedelta(days=1),device_id='lab')).mappings().one()
        assert domain['hostname']=='example.com' and domain['total_scans']==1 and domain['highest_score']==90
        assert db.execute(domain_risk_query(now,now+timedelta(days=1),device_id='other')).all()==[]


def test_cross_device_extension_and_scan_attribution_is_rejected(engine):
    now=datetime(2026,10,9,tzinfo=timezone.utc)
    with Session(engine) as db:
        db.add_all([Device(id='a',name='A'),Device(id='b',name='B')]);db.flush()
        db.add(Extension(id='ext',device_id='a',extension_key='key',name='Extension'));db.flush()
        db.add(Scan(id='scan',device_id='a',extension_id='ext',target_kind='url',target_fingerprint='a'*64,
            target_display='https://example.com',signals=[],score=0,severity='Low',completeness='complete',created_at=now));db.commit()
        with pytest.raises(IntegrityError),db.begin_nested():
            db.add(Scan(device_id='b',extension_id='ext',target_kind='url',target_fingerprint='a'*64,
                target_display='https://example.com',signals=[],score=0,severity='Low',completeness='complete'));db.flush()
        with pytest.raises(IntegrityError),db.begin_nested():
            db.add(Finding(scan_id='scan',device_id='b',signal_code='malicious_url',title='Mismatch',points=80,severity='High'));db.flush()
        with pytest.raises(IntegrityError),db.begin_nested():
            db.add(SecurityEvent(scan_id='scan',device_id='b',event_type='scan_completed',message='Mismatch',severity='High'));db.flush()
