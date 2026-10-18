"""Real password/TOTP sessions, ownership, review safety and database holds."""
from datetime import timedelta
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from alba_security.models import PersonalScan, Scan, utc_now
from alba_security.governance import GovernanceAudit, retention_candidates
from alba_security.user_feedback import UserSecurityFeedback
from tests.alba.test_roles import roles
from tests.alba.test_threat_containment import system
from tests.alba.test_governance import scan, INGEST


def owned(roles):
    client, app, headers, _ = roles
    result = scan(client)
    with app.state.session_factory() as db:
        db.add(PersonalScan(scan_id=result['id'], username='normal_user')); db.commit()
    return result


def payload(result):
    return {'scan_id':result['id'], 'category':'challenge_warning',
            'message':'This warning needs a closer review of the original findings.'}


def test_user_submission_is_linked_deduplicated_and_audited(roles):
    client, app, headers, _ = roles; result=owned(roles)
    response=client.post('/api/feedback',headers=headers['normal_user'],json=payload(result))
    assert response.status_code==201, response.text
    data=response.json()
    assert data['scan_id']==result['id'] and data['reporter']=='normal_user'
    assert data['status']=='pending' and data['outcome'] is None
    assert data['created_at'].endswith('+00:00')
    assert client.post('/api/feedback',headers=headers['normal_user'],json=payload(result)).status_code==409
    with app.state.session_factory() as db:
        audit=db.scalar(select(GovernanceAudit).where(GovernanceAudit.reference==data['id']))
        assert audit.actor=='normal_user' and audit.action=='submitted'
        assert 'message' not in audit.details


def test_user_cannot_reference_other_or_missing_scans(roles):
    client, _, headers, _=roles; other=scan(client)
    for scan_id in (other['id'],'nonexistent'):
        response=client.post('/api/feedback',headers=headers['normal_user'],json={**payload(other),'scan_id':scan_id})
        assert response.status_code==404
    assert client.post('/api/feedback',headers=headers['head_administrator'],json={**payload(other),'scan_id':'nonexistent'}).status_code==404


def test_user_and_manager_see_only_their_submissions_admin_sees_both(roles):
    client, _, headers, _=roles; result=owned(roles)
    for role in ('normal_user','manager'):
        assert client.post('/api/feedback',headers=headers[role],json=payload(result)).status_code==201
    for role in ('normal_user','manager'):
        rows=client.get('/api/feedback',headers=headers[role]).json()
        assert len(rows)==1 and rows[0]['reporter']==role
    for role in ('administrator','head_administrator'):
        assert len(client.get('/api/feedback',headers=headers[role]).json())==2


@pytest.mark.parametrize('role',['administrator','head_administrator'])
def test_admin_review_preserves_verdict_blocks_alerts_and_case(roles,role):
    client, app, headers, _=roles; result=owned(roles)
    before=client.get('/api/scans/'+result['id'],headers=headers[role]).json()
    blocks_before=client.get('/api/threat-blocks',headers=headers[role]).json()
    cases_before=client.get('/api/cases',headers=headers[role]).json()
    feedback=client.post('/api/feedback',headers=headers['normal_user'],json=payload(result)).json()
    path='/api/feedback/'+feedback['id']+'/review'
    body={'expected_revision':1,'outcome':'false_positive','review_note':'Original evidence reviewed; arrange an independent follow-up scan.'}
    response=client.post(path,headers=headers[role],json=body)
    assert response.status_code==200,response.text
    data=response.json()
    assert data['status']=='reviewed' and data['reviewed_by']==('hasan' if role=='head_administrator' else role) and data['revision']==2
    assert data['review_note']==body['review_note']
    assert client.post(path,headers=headers[role],json=body).status_code==409
    after=client.get('/api/scans/'+result['id'],headers=headers[role]).json()
    assert after==before
    assert client.get('/api/threat-blocks',headers=headers[role]).json()==blocks_before
    assert client.get('/api/cases',headers=headers[role]).json()==cases_before
    mine=client.get('/api/feedback?status=reviewed',headers=headers['normal_user']).json()
    assert mine[0]['outcome']=='false_positive'
    assert client.get('/api/feedback?status=pending',headers=headers[role]).json()==[]


@pytest.mark.parametrize('role',['normal_user','manager'])
def test_review_is_admin_only(roles,role):
    client, _, headers, _=roles; result=owned(roles)
    item=client.post('/api/feedback',headers=headers['normal_user'],json=payload(result)).json()
    response=client.post('/api/feedback/'+item['id']+'/review',headers=headers[role],json={
        'expected_revision':1,'outcome':'inconclusive','review_note':'More evidence is needed before reaching a decision.'})
    assert response.status_code==403


def test_unauthenticated_ingestion_and_challenge_tokens_are_rejected(roles):
    client, _, _, _=roles
    challenge=client.post('/api/admin/login',json={'username':'hasan','password':'primary-test-password'}).json()
    for header in ({},INGEST,{'Authorization':'Bearer '+challenge['challenge_token']}):
        assert client.get('/api/feedback',headers=header).status_code==401
        assert client.post('/api/feedback',headers=header,json={}).status_code==401
        assert client.post('/api/feedback/missing/review',headers=header,json={}).status_code==401


@pytest.mark.parametrize('change',[
    {'message':'   '}, {'message':'a'*2001}, {'category':'approve'},
    {'reporter':'hasan'}, {'status':'reviewed'}, {'scan_id':''},
])
def test_submission_validation_and_spoofing(roles,change):
    client, _, headers, _=roles; result=owned(roles)
    assert client.post('/api/feedback',headers=headers['normal_user'],json={**payload(result),**change}).status_code==422


def test_revision_privacy_pagination_and_retention(roles):
    client, app, headers, _=roles; result=owned(roles); h=headers['head_administrator']
    item=client.post('/api/feedback',headers=headers['normal_user'],json=payload(result)).json()
    body={'expected_revision':9,'outcome':'inconclusive','review_note':'The available evidence does not resolve this concern.'}
    assert client.post('/api/feedback/'+item['id']+'/review',headers=h,json=body).status_code==409
    assert client.get('/api/feedback?limit=1&offset=1',headers=h).json()==[]
    assert client.get('/api/feedback?limit=201',headers=h).status_code==422
    assert client.get('/api/feedback?status=invalid',headers=h).status_code==422
    assert client.post('/api/feedback/missing/review',headers=h,json=body).status_code==404
    rules=client.get('/api/privacy',headers=h).json()
    settings={key:rules[key] for key in ('collection_purpose','retention_days')}
    assert client.post('/api/privacy',headers=h,json={**settings,'show_hostnames':False,'expected_revision':rules['revision'],'reason':'Minimize hostnames in the feedback workspace'}).status_code==200
    listing=client.get('/api/feedback',headers=h).json()
    assert 'private.example' not in str(listing)
    # Use a separate harmless scan: no cases, blocks or alerts can cause the hold.
    harmless=scan(client,detected='malicious_url',status='clear')
    assert client.post('/api/feedback',headers=h,json=payload(harmless)).status_code==201
    with app.state.session_factory() as db:
        db.get(Scan,harmless['id']).created_at=utc_now()-timedelta(days=400); db.commit()
        assert harmless['id'] not in retention_candidates(db)[0]


def test_database_rejects_invalid_review_state(roles):
    client, app, headers, _=roles; result=owned(roles)
    row=client.post('/api/feedback',headers=headers['normal_user'],json=payload(result)).json()
    with app.state.session_factory() as db:
        with pytest.raises(IntegrityError):
            db.execute(update(UserSecurityFeedback).where(UserSecurityFeedback.id==row['id']).values(status='reviewed'))
            db.commit()
        db.rollback()
