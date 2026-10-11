from datetime import datetime,timedelta,timezone
import pytest
from sqlalchemy import select,func
from alba_security.automatic_reports import scheduled_period,generate_scheduled_report
from alba_security.intelligence import IntelligenceReport,PeriodRequest,prepare_period_report
from alba_security.governance import GovernanceAudit
from tests.alba.test_intelligence import model_fixture
from test_threat_containment import system,submit

def test_sunday_report_covers_previous_seven_complete_utc_days():
    payload,(start,end)=scheduled_period('weekly',datetime(2026,10,11,6,tzinfo=timezone.utc))
    assert payload.period=='2026-10-04'
    assert start.weekday()==6 and end==datetime(2026,10,11,tzinfo=timezone.utc)
    assert end-start==timedelta(days=7)

def test_monthly_first_day_uses_closed_month_and_handles_january():
    assert scheduled_period('monthly',datetime(2027,1,1,6,tzinfo=timezone.utc))[0].period=='2026-12'
    with pytest.raises(ValueError):scheduled_period('weekly',datetime(2026,10,11))

def test_scheduler_saves_once_and_does_not_call_llm_on_retry(system):
    _,app,_,_=system
    model=model_fixture()
    with app.state.session_factory() as db:
        first,created=generate_scheduled_report(db,'weekly',now=datetime(2026,10,11,6,tzinfo=timezone.utc),client=model,model='test-model')
        second,again=generate_scheduled_report(db,'weekly',now=datetime(2026,10,11,7,tzinfo=timezone.utc),client=model,model='test-model')
        assert created and not again and first.id==second.id
        assert model.responses.create.call_count==1
        assert db.scalar(select(func.count()).select_from(IntelligenceReport))==1
        assert db.scalar(select(GovernanceAudit).where(GovernanceAudit.action=='scheduled_report_generated'))

def test_scheduled_windows_cannot_include_incomplete_or_malformed_week(system):
    _,app,_,_=system
    now=datetime(2026,10,11,6,tzinfo=timezone.utc)
    with app.state.session_factory() as db:
        for start,end in [(now,now+timedelta(days=7)),(now-timedelta(days=7),now),(now-timedelta(days=8),now)]:
            with pytest.raises(ValueError):prepare_period_report(db,PeriodRequest(kind='weekly',period=start.date().isoformat()),now=now,scheduled_bounds=(start,end))

def test_failed_llm_does_not_save_a_fake_report_and_retry_can_succeed(system):
    _,app,_,_=system
    model=model_fixture()
    model.responses.create.side_effect=RuntimeError('synthetic local inference failure')
    with app.state.session_factory() as db:
        with pytest.raises(Exception):generate_scheduled_report(db,'monthly',now=datetime(2026,10,11,tzinfo=timezone.utc),client=model,model='test-model')
        assert db.scalar(select(func.count()).select_from(IntelligenceReport))==0
        record,created=generate_scheduled_report(db,'monthly',now=datetime(2026,10,11,tzinfo=timezone.utc),client=model_fixture(),model='test-model')
        assert created and record.period=='2026-09'

def test_schedule_requires_sign_in_and_exposes_no_secrets(system,monkeypatch):
    client,_,headers,_=system
    monkeypatch.setenv('REPORT_AUTOMATION_ENABLED','1')
    assert client.get('/api/intelligence/report-schedule').status_code==401
    result=client.get('/api/intelligence/report-schedule',headers=headers['hasan'])
    assert result.status_code==200 and result.json()['enabled'] is True
    assert result.json()['time_zone']=='Asia/Riyadh' and result.json()['weekly_day']=='Sunday'
    assert result.json()['monthly_day']==1 and result.headers['cache-control']=='no-store'

@pytest.mark.parametrize('kind,target,signal',[('url','https://critical.example/','malicious_url'),('download','a'*64,'malicious_file_hash')])
def test_critical_always_creates_open_alert_block_and_case(system,kind,target,signal):
    client,app,headers,_=system
    if kind=='url':
        assert client.post('/api/overrides',headers=headers['hasan'],json={'kind':'domain','target':'critical.example','reason':'Controlled regression exception'}).status_code==201
    result=submit(client,code=signal,kind=kind,target=target)
    assert result['severity']=='Critical'
    assert result['containment']['active'] and result['containment']['case_id']
    alerts=client.get('/api/alerts',headers=headers['hasan']).json()
    assert any(row['scan_id']==result['id'] and row['status']=='open' for row in alerts)
    assert client.get('/api/cases/'+result['containment']['case_id'],headers=headers['hasan']).status_code==200
