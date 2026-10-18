"""Suggestion ownership, authenticated review and durable administrator responses."""
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from alba_security.governance import GovernanceAudit
from alba_security.user_suggestions import UserSuggestion
from tests.alba.test_roles import roles
from tests.alba.test_threat_containment import system
from tests.alba.test_governance import INGEST

IDEA={'title':'Clearer extension controls','category':'interface',
      'description':'Explain the difference between disabling an extension and removing its inventory record.'}


def submit(client, header, **changes):
    response=client.post('/api/suggestions',headers=header,json=IDEA|changes)
    assert response.status_code==201,response.text
    return response.json()


def test_suggestion_needs_no_scan_and_cannot_spoof_identity(roles):
    client, app, headers, _=roles
    row=submit(client,headers['normal_user'])
    assert row['reporter']=='normal_user' and row['status']=='new' and row['revision']==1
    assert row['created_at'].endswith('+00:00') and row['response'] is None
    assert 'content_digest' not in row
    assert client.post('/api/suggestions',headers=headers['normal_user'],json=IDEA|{'reporter':'hasan'}).status_code==422
    assert client.post('/api/suggestions',headers=headers['normal_user'],json=IDEA).status_code==409
    with app.state.session_factory() as db:
        audit=db.scalar(select(GovernanceAudit).where(GovernanceAudit.reference==row['id']))
        assert audit.action=='submitted' and audit.actor=='normal_user'
        assert 'description' not in audit.details and 'title' not in audit.details


def test_listing_is_private_except_for_administrators(roles):
    client, _, headers, _=roles
    for role in ('normal_user','manager','administrator','head_administrator'):
        submit(client,headers[role])
    for role in ('normal_user','manager'):
        rows=client.get('/api/suggestions',headers=headers[role]).json()
        assert len(rows)==1 and rows[0]['reporter']==role
    for role in ('administrator','head_administrator'):
        assert len(client.get('/api/suggestions',headers=headers[role]).json())==4


@pytest.mark.parametrize('role',['administrator','head_administrator'])
def test_admin_response_and_status_history_are_visible_to_submitter(roles,role):
    client, app, headers, _=roles
    row=submit(client,headers['normal_user']);url='/api/suggestions/'+row['id']+'/review'
    before=client.get('/api/risk-policy',headers=headers[role]).json()
    for revision,status in enumerate(('under_review','planned','completed'),1):
        response=client.post(url,headers=headers[role],json={'expected_revision':revision,
            'status':status,'response':'Reviewed the idea and recorded the next implementation step.'})
        assert response.status_code==200,response.text
        saved=response.json()
        assert saved['status']==status and saved['revision']==revision+1
        assert saved['reviewed_by']==('hasan' if role=='head_administrator' else role)
        assert saved['reviewed_at'].endswith('+00:00')
    rows=client.get('/api/suggestions?status=completed',headers=headers['normal_user']).json()
    assert rows[0]['response']==saved['response']
    assert client.get('/api/suggestions?status=new',headers=headers['normal_user']).json()==[]
    assert client.get('/api/risk-policy',headers=headers[role]).json()==before
    with app.state.session_factory() as db:
        reviews=list(db.scalars(select(GovernanceAudit).where(GovernanceAudit.reference==row['id'],GovernanceAudit.action=='reviewed')))
        assert len(reviews)==3 and all('response' not in r.details for r in reviews)


@pytest.mark.parametrize('role',['normal_user','manager'])
def test_lower_roles_cannot_review_even_own_suggestion(roles,role):
    client, _, headers, _=roles;row=submit(client,headers[role])
    assert client.post('/api/suggestions/'+row['id']+'/review',headers=headers[role],json={
        'expected_revision':1,'status':'planned','response':'This attempt must not change administrator decisions.'}).status_code==403


def test_review_rejects_stale_revision_missing_reference_and_invalid_response(roles):
    client, _, headers, _=roles;h=headers['head_administrator'];row=submit(client,headers['normal_user'])
    body={'expected_revision':1,'status':'declined','response':'This idea duplicates an existing feature in the current extension.'}
    path='/api/suggestions/'+row['id']+'/review'
    assert client.post(path,headers=h,json=body).status_code==200
    assert client.post(path,headers=h,json=body).status_code==409
    assert client.post('/api/suggestions/missing/review',headers=h,json=body).status_code==404
    for change in ({'status':'new'},{'status':'approved'},{'response':' '},{'expected_revision':True},{'reporter':'hasan'}):
        assert client.post(path,headers=h,json=body|change).status_code==422


def test_session_authentication_required(roles):
    client, _, _, _=roles
    challenge=client.post('/api/admin/login',json={'username':'hasan','password':'primary-test-password'}).json()
    for header in ({},INGEST,{'Authorization':'Bearer '+challenge['challenge_token']}):
        for method,path,body in [('GET','/api/suggestions',None),('POST','/api/suggestions',IDEA),('POST','/api/suggestions/id/review',{})]:
            assert client.request(method,path,headers=header,json=body).status_code==401


@pytest.mark.parametrize('change',[{'title':' '},{'title':'x'*161},{'description':'short'},
    {'description':'x'*3001},{'category':'scan'},{'status':'completed'}])
def test_invalid_or_privileged_submission_fields_rejected(roles,change):
    client, _, headers, _=roles
    assert client.post('/api/suggestions',headers=headers['normal_user'],json=IDEA|change).status_code==422


def test_filters_pages_and_database_review_constraint(roles):
    client, app, headers, _=roles;h=headers['head_administrator']
    row=submit(client,headers['normal_user'])
    assert client.get('/api/suggestions?limit=1&offset=1',headers=h).json()==[]
    assert client.get('/api/suggestions?status=other',headers=h).status_code==422
    assert client.get('/api/suggestions?limit=201',headers=h).status_code==422
    assert client.get('/api/suggestions?offset=-1',headers=h).status_code==422
    with app.state.session_factory() as db:
        with pytest.raises(IntegrityError):
            db.execute(update(UserSuggestion).where(UserSuggestion.id==row['id']).values(status='planned'))
            db.commit()
        db.rollback()
    assert client.get('/api/suggestions',headers=headers['normal_user']).json()[0]['status']=='new'
