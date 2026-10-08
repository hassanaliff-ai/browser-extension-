"""Repeated visits, expiry, permanent whitelist and role checks through the API."""
from datetime import timedelta
import pytest
from sqlalchemy import select
from alba_security.models import utc_now
from alba_security.website_access import WebsiteRequest, WebsiteWhitelist, FOREVER
from tests.alba.test_governance import system  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401
from tests.alba.test_website_access import create, URL, REASON


def grant(client, headers, request, **options):
    return client.post('/api/access/requests/'+request['id']+'/review',headers=headers,
        json={'decision':'temporary','expected_revision':request['revision'],'reason':REASON,'confirmed':True,**options})


@pytest.mark.parametrize('hours',[24,168])
def test_temporary_repeated_visits_and_expiry_require_new_request(roles,monkeypatch,hours):
    client,app,h,_=roles
    request=create(client,h['normal_user'])
    before=utc_now()
    result=grant(client,h['manager'],request,duration_hours=hours)
    assert result.status_code==200,result.text
    with app.state.session_factory() as db:
        expiry=db.get(WebsiteRequest,request['id']).expires_at
        from alba_security.admin_auth import _utc
        assert before+timedelta(hours=hours)<=_utc(expiry)<=utc_now()+timedelta(hours=hours)
    for _ in range(3):
        result=client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL})
        assert result.status_code==200 and result.json()['kind']=='temporary'
    assert client.post('/api/access/consume',headers=h['administrator'],json={'target':URL}).status_code==403
    assert create(client,h['normal_user'])['id']==request['id']
    # Account clock stays real; only the website permission clock is advanced.
    from alba_security.admin_auth import _utc
    monkeypatch.setattr('alba_security.website_access.utc_now',lambda:_utc(expiry))
    assert not client.post('/api/access/check',headers=h['normal_user'],json={'target':URL}).json()['allowed']
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).status_code==403
    renewed=create(client,h['normal_user'])
    assert renewed['id']!=request['id'] and renewed['status']=='pending'


def test_forever_whitelist_is_reusable_has_no_public_expiry_and_can_be_revoked(roles,monkeypatch):
    client,app,h,_=roles
    request=create(client,h['head_administrator'])
    result=grant(client,h['head_administrator'],request,decision='whitelist',whitelist_forever=True)
    assert result.status_code==200,result.text
    assert result.json()['permanent'] is True and result.json()['expires_at'] is None
    with app.state.session_factory() as db:
        row=db.scalar(select(WebsiteWhitelist))
        assert row.expires_at.replace(tzinfo=FOREVER.tzinfo)==FOREVER
    future=utc_now()+timedelta(days=365*30)
    monkeypatch.setattr('alba_security.website_access.utc_now',lambda:future)
    for role in h:
        for _ in range(2):
            result=client.post('/api/access/consume',headers=h[role],json={'target':URL})
            assert result.status_code==200
            assert result.json()['permanent'] is True and result.json()['expires_at'] is None
    entry=client.get('/api/access/whitelist',headers=h['head_administrator']).json()[0]
    assert entry['permanent'] is True
    assert create(client,h['normal_user'])['status']=='approved'
    with app.state.session_factory() as db:
        assert len(list(db.scalars(select(WebsiteRequest))))==1
    assert client.post('/api/access/check',headers=h['normal_user'],json={'target':URL+'/other'}).json()['allowed'] is False
    assert client.post('/api/access/whitelist/'+entry['id']+'/revoke',headers=h['head_administrator'],json={'reason':REASON}).status_code==200
    assert not client.post('/api/access/check',headers=h['normal_user'],json={'target':URL}).json()['allowed']
    with app.state.session_factory() as db:
        assert db.get(WebsiteRequest,request['id']).status=='revoked'
    assert create(client,h['normal_user'])['status']=='pending'


@pytest.mark.parametrize('hours',[0,1,7,25,169,True,'24'])
def test_unapproved_durations_are_rejected(roles,hours):
    client,_,h,_=roles
    request=create(client,h['normal_user'])
    assert grant(client,h['manager'],request,duration_hours=hours).status_code==422


def test_duration_choices_do_not_bypass_role_hierarchy(roles):
    client,_,h,_=roles
    request=create(client,h['administrator'])
    assert grant(client,h['manager'],request,duration_hours=24).status_code==403
    assert grant(client,h['manager'],request,decision='whitelist',whitelist_forever=True).status_code==403
    assert grant(client,h['head_administrator'],request,duration_hours=168).status_code==200
