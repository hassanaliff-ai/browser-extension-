"""Isolated regression tests; no production keys, provider calls or live records."""
import base64
from datetime import datetime,timedelta,timezone
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from sqlalchemy import select,func

from alba_security import cloud_reports as cloud
from alba_security.governance import GovernanceAudit
from alba_security.intelligence import IntelligenceReport
from alba_security.models import Scan,Alert
from alba_security.report_job import MonthlyReportRecord
from tests.alba.test_governance import system,scan

UTC=timezone.utc
HEADERS={'Authorization':'Bearer isolated-workflow-identity'}
PREFIX='/api/intelligence/report-automation/'


@pytest.fixture
def worker(monkeypatch,system):
    monkeypatch.setenv('CLOUD_REPORT_AUTOMATION_ENABLED','1')
    monkeypatch.setenv('INGEST_TOKEN','isolated-report-signing-key')
    monkeypatch.setenv('REPORT_LANGUAGE','en')
    monkeypatch.setattr(cloud.IDENTITY,'verify',lambda token: {'run_id':'123'})
    return system


def test_weekly_and_monthly_windows_wait_for_09_ksa_and_catch_up():
    before=datetime(2026,11,1,5,59,tzinfo=UTC)
    after=before+timedelta(minutes=1)
    assert cloud._last_week_end(before)==datetime(2026,10,25,tzinfo=UTC)
    assert cloud._last_week_end(after)==datetime(2026,11,1,tzinfo=UTC)
    assert cloud._last_month_end(before)==datetime(2026,10,1,tzinfo=UTC)
    assert cloud._last_month_end(after)==datetime(2026,11,1,tzinfo=UTC)
    due=cloud.periods_due(datetime(2027,1,1,6,tzinfo=UTC),datetime(2026,10,4,6,tzinfo=UTC))
    assert {'2026-09','2026-10','2026-11','2026-12'} <= {p for k,p,_,_ in due if k=='monthly'}
    assert len({(k,p)for k,p,_,_ in due})==len(due)
    assert all(end<=datetime(2027,1,1,6,tzinfo=UTC)for _,_,_,end in due)


@pytest.fixture(scope='module')
def signer():
    return rsa.generate_private_key(public_exponent=65537,key_size=2048)


def identity_token(signer,changes=None,*,algorithm='RS256'):
    now=int(time.time())
    claims={'iss':cloud.ISSUER,'aud':cloud.AUDIENCE,'repository':cloud.REPOSITORY,
        'repository_id':cloud.REPOSITORY_ID,'repository_owner_id':cloud.OWNER_ID,
        'ref':'refs/heads/main','workflow_ref':cloud.WORKFLOW,'runner_environment':'github-hosted',
        'repository_visibility':'public','event_name':'schedule','run_id':'123456','sha':'a'*40,
        'iat':now,'nbf':now-1,'exp':now+300}
    claims.update(changes or {})
    head=cloud._b64(json.dumps({'alg':algorithm,'kid':'test-key'}).encode())
    body=cloud._b64(json.dumps(claims).encode())
    signed=(head+'.'+body).encode()
    sig=signer.sign(signed,padding.PKCS1v15(),hashes.SHA256())
    verifier=cloud.GitHubIdentity();verifier.keys={'test-key':signer.public_key()};verifier.expires=time.monotonic()+900
    return verifier,head+'.'+body+'.'+cloud._b64(sig)


def test_real_rs256_signature_is_verified(signer):
    verifier,token=identity_token(signer)
    assert verifier.verify(token)['repository_id']==cloud.REPOSITORY_ID
    with pytest.raises(Exception):verifier.verify(token[:-5]+'aaaaa')


@pytest.mark.parametrize('changes',[
 {'iss':'https://untrusted.example'}, {'aud':'other'}, {'repository':'attacker/fork'},
 {'repository_id':'0'}, {'repository_owner_id':'0'}, {'ref':'refs/pull/1/merge'},
 {'workflow_ref':cloud.WORKFLOW.replace('cloud-reports','different')},
 {'job_workflow_ref':'untrusted/reusable'}, {'runner_environment':'self-hosted'},
 {'repository_visibility':'private'}, {'event_name':'pull_request'},
 {'exp':1},{'iat':9999999999},{'nbf':9999999999},{'run_id':'not-a-run'},{'sha':'untrusted'},
])
def test_oidc_rejects_wrong_repository_ref_workflow_event_and_clock(signer,changes):
    verifier,token=identity_token(signer,changes)
    with pytest.raises(Exception):verifier.verify(token)


def test_oidc_does_not_accept_an_unsigned_algorithm(signer):
    verifier,token=identity_token(signer,algorithm='none')
    with pytest.raises(Exception):verifier.verify(token)


def test_disabled_cloud_routes_fail_closed(system,monkeypatch):
    monkeypatch.setenv('CLOUD_REPORT_AUTOMATION_ENABLED','0')
    client,_,_,_=system
    assert client.post(PREFIX+'tick',json={}).status_code==503


def test_an_account_session_is_not_a_workflow_identity(system,monkeypatch):
    monkeypatch.setenv('CLOUD_REPORT_AUTOMATION_ENABLED','1')
    monkeypatch.setattr(cloud.IDENTITY,'verify',lambda token: (_ for _ in ()).throw(ValueError()))
    client,_,headers,_=system
    assert client.post(PREFIX+'tick',json={}).status_code==401
    assert client.post(PREFIX+'tick',json={},headers=headers['hasan']).status_code==401


def test_tick_returns_no_data_and_saves_empty_periods_once(worker,monkeypatch):
    from alba_security import llm
    monkeypatch.setattr(llm,'write_narrative',lambda *a,**k:(_ for _ in ()).throw(AssertionError('No LLM allowed')))
    client,app,_,_=worker
    for _ in range(2):
        response=client.post(PREFIX+'tick',json={},headers=HEADERS)
        assert response.status_code==204 and response.content==b''
    with app.state.session_factory()as db:
        rows=db.scalars(select(IntelligenceReport)).all()
        assert len(rows)==2 and {r.kind for r in rows}=={'weekly','monthly'}
        for row in rows:
            assert row.stats['total_scans']==0
            assert row.narrative['source']=='verified_statistics' and row.narrative['model'] is None
            assert 'No scans were recorded' in row.body
            assert 'no language model was used' in row.body
        monthly=db.scalar(select(MonthlyReportRecord))
        assert monthly.stats['machine_learning']['status']=='insufficient_history'
        assert db.scalar(select(func.count()).select_from(Scan))==0
        assert db.scalar(select(func.count()).select_from(Alert))==0


@pytest.mark.parametrize('action',['jobs','complete','failed'])
def test_old_data_transfer_endpoints_no_longer_exist(worker,action):
    client,_,_,_=worker
    assert client.post(PREFIX+action,json={},headers=HEADERS).status_code==404


def test_worker_identity_cannot_read_reports_or_raw_scans(system,monkeypatch):
    monkeypatch.setenv('CLOUD_REPORT_AUTOMATION_ENABLED','1')
    client,_,_,_=system
    for path in ['/api/intelligence/reports','/api/scans','/api/admin/accounts']:
        assert client.get(path,headers=HEADERS).status_code==401


def test_failure_is_generic_and_recorded_only_in_database(worker,monkeypatch):
    client,app,_,_=worker
    monkeypatch.setattr(cloud,'_snapshot',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('PRIVATE credentials')))
    response=client.post(PREFIX+'tick',json={},headers=HEADERS)
    assert response.status_code==503 and 'PRIVATE' not in response.text
    with app.state.session_factory()as db:
        assert db.scalar(select(func.count()).select_from(IntelligenceReport))==0
        event=db.scalar(select(GovernanceAudit).where(GovernanceAudit.action=='cloud_worker_failed'))
        assert event and 'PRIVATE' not in json.dumps(event.details)


def test_private_status_and_sources_are_honest(worker):
    client,app,headers,_=worker
    response=client.post(PREFIX+'tick',json={},headers=HEADERS)
    assert response.status_code==204 and not response.content
    status=client.get('/api/intelligence/report-schedule',headers=headers['hasan'])
    data=status.json()
    assert data['mode']=='github_trigger' and data['laptop_required'] is False
    assert data['report_mode']=='verified_statistics' and data['llm_available'] is False
    assert data['data_shared_with_github'] is False
    assert 'ticket' not in status.text and 'isolated-report-signing' not in status.text
    assert client.get('/api/intelligence/report-schedule').status_code==401


def test_raw_targets_never_leave_trigger_response(worker):
    client,_,_,_=worker
    scan(client)
    response=client.post(PREFIX+'tick',json={},headers=HEADERS)
    assert response.status_code==204 and response.content==b''


def test_manual_request_is_queued_once_and_generated_without_a_model(worker):
    client,app,headers,_=worker
    now=cloud.utc_now();period=(now-timedelta(days=now.weekday()+7)).date().isoformat()
    for _ in range(2):
        result=client.post('/api/intelligence/reports/generate',headers=headers['hasan'],
            json={'kind':'weekly','period':period,'language':'en'})
        assert result.status_code==200 and result.json()['status']=='queued'
    assert client.post(PREFIX+'tick',json={},headers=HEADERS).status_code==204
    with app.state.session_factory()as db:
        record=db.scalar(select(IntelligenceReport).where(IntelligenceReport.period==period))
        assert record and record.narrative['source']=='verified_statistics'
        assert db.scalar(select(func.count()).select_from(GovernanceAudit).where(GovernanceAudit.action=='cloud_report_requested'))==1


def test_stored_success_survives_105_heartbeat_rows(worker):
    client,app,headers,_=worker
    assert client.post(PREFIX+'tick',json={},headers=HEADERS).status_code==204
    with app.state.session_factory()as db:
        for _ in range(105):cloud.audit(db,cloud.AREA,'worker',cloud.ACTOR,'cloud_worker_checked')
        db.commit()
    status=client.get('/api/intelligence/report-schedule',headers=headers['hasan']).json()
    assert all(status['runs'][kind]['last_success'] for kind in ['weekly','monthly'])


def test_arabic_report_is_statistical_and_does_not_invent_activity(worker,monkeypatch):
    monkeypatch.setenv('REPORT_LANGUAGE','ar')
    client,app,_,_=worker
    assert client.post(PREFIX+'tick',json={},headers=HEADERS).status_code==204
    with app.state.session_factory()as db:
        rows=db.scalars(select(IntelligenceReport)).all()
        assert all(row.language=='ar' and row.narrative['source']=='verified_statistics' for row in rows)
        assert all('لم تُسجل عمليات فحص' in row.body for row in rows)
