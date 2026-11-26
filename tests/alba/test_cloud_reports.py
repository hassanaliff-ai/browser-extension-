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


def complete_payload(job,summary=None):
    return {'ticket':job['ticket'],'model':cloud.MODEL,'model_digest':cloud.MODEL_DIGEST,
        'narrative':{'summary':summary or 'No scans, alerts or AI explanations were recorded during this period. No recorded activity does not establish safety.',
                     'evidence_codes':job['evidence_codes'],'recommendation_codes':['investigate']}}


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
    assert client.post(PREFIX+'jobs',json={}).status_code==503


def test_an_account_session_is_not_a_workflow_identity(system,monkeypatch):
    monkeypatch.setenv('CLOUD_REPORT_AUTOMATION_ENABLED','1')
    monkeypatch.setattr(cloud.IDENTITY,'verify',lambda token: (_ for _ in ()).throw(ValueError()))
    client,_,headers,_=system
    assert client.post(PREFIX+'jobs',json={}).status_code==401
    assert client.post(PREFIX+'jobs',json={},headers=headers['hasan']).status_code==401


def test_jobs_are_aggregate_only_and_empty_periods_are_generated_once(worker):
    client,app,_,_=worker
    response=client.post(PREFIX+'jobs',json={},headers=HEADERS)
    assert response.status_code==200,response.text
    jobs=response.json()['jobs'];assert len(jobs)==2
    assert {j['kind']for j in jobs}=={'weekly','monthly'}
    for job in jobs:
        assert job['stats']['total_scans']==0
        assert 'archive' not in job['stats'] and 'device_id' not in json.dumps(job)
        result=client.post(PREFIX+'complete',json=complete_payload(job),headers=HEADERS)
        assert result.status_code==200,result.text
        again=client.post(PREFIX+'complete',json=complete_payload(job),headers=HEADERS)
        assert again.json()['status']=='already_saved'
    with app.state.session_factory()as db:
        assert db.scalar(select(func.count()).select_from(IntelligenceReport))==2
        monthly=db.scalar(select(MonthlyReportRecord))
        assert monthly and monthly.stats['machine_learning']['status']=='insufficient_history'
        assert db.scalar(select(func.count()).select_from(Scan))==0
        assert db.scalar(select(func.count()).select_from(Alert))==0
    assert client.post(PREFIX+'jobs',json={},headers=HEADERS).json()['jobs']==[]


def test_snapshot_tampering_and_invented_model_are_rejected(worker):
    client,_,_,_=worker
    job=client.post(PREFIX+'jobs',json={'limit':1},headers=HEADERS).json()['jobs'][0]
    payload=complete_payload(job);payload['ticket']=payload['ticket'][:-5]+'abcde'
    assert client.post(PREFIX+'complete',json=payload,headers=HEADERS).status_code==422
    payload=complete_payload(job);payload['model']='unapproved-model'
    assert client.post(PREFIX+'complete',json=payload,headers=HEADERS).status_code==422
    payload=complete_payload(job);payload['model_digest']='0'*64
    assert client.post(PREFIX+'complete',json=payload,headers=HEADERS).status_code==422


def test_changed_historical_evidence_requires_a_fresh_snapshot(worker):
    client,app,_,_=worker
    job=client.post(PREFIX+'jobs',json={},headers=HEADERS).json()['jobs'][0]
    record=scan(client)
    with app.state.session_factory()as db:
        row=db.get(Scan,record['id']);row.created_at=datetime.fromisoformat(job['stats']['start_utc'])+timedelta(hours=1);db.commit()
    result=client.post(PREFIX+'complete',json=complete_payload(job),headers=HEADERS)
    assert result.status_code==409,result.text
    with app.state.session_factory()as db:assert db.scalar(select(func.count()).select_from(IntelligenceReport))==0


def test_untrusted_summary_does_not_save_and_failure_is_durable(worker):
    client,app,headers,_=worker
    job=client.post(PREFIX+'jobs',json={'limit':1},headers=HEADERS).json()['jobs'][0]
    payload=complete_payload(job,'Visit https://untrusted.example/ to resolve all security issues in this period.')
    assert client.post(PREFIX+'complete',json=payload,headers=HEADERS).status_code==422
    with app.state.session_factory()as db:
        assert db.scalar(select(func.count()).select_from(IntelligenceReport))==0
        assert db.scalar(select(GovernanceAudit).where(GovernanceAudit.action=='cloud_report_failed'))
    status=client.get('/api/intelligence/report-schedule',headers=headers['hasan']).json()
    assert status['mode']=='github_actions' and status['laptop_required'] is False
    assert status['runs'][job['kind']]['last_attempt']['status']=='failed'
    assert client.get('/api/intelligence/report-schedule').status_code==401


def test_claims_and_status_do_not_expose_raw_targets(worker):
    client,_,headers,_=worker
    scan(client)
    response=client.post(PREFIX+'jobs',json={},headers=HEADERS)
    assert 'PRIVATE' not in response.text and 'private.example' not in response.text
    status=client.get('/api/intelligence/report-schedule',headers=headers['hasan'])
    assert 'ticket' not in status.text and 'isolated-report-signing' not in status.text


def test_manual_request_is_queued_idempotently_and_preserves_monday_weeks(worker):
    client,app,headers,_=worker
    current=cloud.utc_now();monday=current-timedelta(days=current.weekday()+7)
    period=monday.date().isoformat()
    for _ in range(2):
        response=client.post('/api/intelligence/reports/generate',headers=headers['hasan'],
            json={'kind':'weekly','period':period,'language':'en'})
        assert response.status_code==200 and response.json()['status']=='queued'
    with app.state.session_factory()as db:
        assert db.scalar(select(func.count()).select_from(GovernanceAudit).where(GovernanceAudit.action=='cloud_report_requested'))==1
    job=client.post(PREFIX+'jobs',json={},headers=HEADERS).json()['jobs'][0]
    assert job['period']==period
    assert client.post(PREFIX+'complete',json=complete_payload(job),headers=HEADERS).status_code==200


def test_stored_success_survives_more_than_100_heartbeat_rows(worker):
    client,app,headers,_=worker
    job=client.post(PREFIX+'jobs',json={'limit':1},headers=HEADERS).json()['jobs'][0]
    assert client.post(PREFIX+'complete',json=complete_payload(job),headers=HEADERS).status_code==200
    with app.state.session_factory()as db:
        for _ in range(105):cloud.audit(db,cloud.AREA,'worker',cloud.ACTOR,'cloud_worker_checked')
        db.commit()
    result=client.get('/api/intelligence/report-schedule',headers=headers['hasan']).json()
    assert result['runs'][job['kind']]['last_success']
