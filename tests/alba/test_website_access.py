"""Website approvals use real role sessions, durable state and atomic consumption."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import select
from tests.alba.test_governance import system  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401
from alba_security.governance import GovernanceAudit
from alba_security.models import utc_now
from alba_security.website_access import WebsiteRequest, WebsiteWhitelist

URL = 'https://example.com/approved'
REASON = 'Required to review documentation for the assigned project'

def create(client, header, target=URL):
    response = client.post('/api/access/requests', headers=header, json={'target': target, 'reason': REASON})
    assert response.status_code == 201, response.text
    return response.json()

def review(client, header, request, decision='once', revision=None):
    return client.post('/api/access/requests/'+request['id']+'/review', headers=header,
        json={'decision': decision, 'expected_revision': revision or request['revision'],
              'whitelist_days': 30, 'confirmed': True, 'reason': 'Verified this destination and the documented business need'})

def test_anonymous_users_cannot_request_review_or_consume(roles):
    client, _, _, _ = roles
    for method, path in [('GET','requests'),('GET','whitelist'),('POST','requests'),('POST','check'),
                         ('POST','consume'),('POST','requests/missing/review'),('POST','whitelist/missing/revoke')]:
        result = client.request(method, '/api/access/'+path, json={'target':URL,'reason':REASON} if method == 'POST' else None)
        assert result.status_code == 401
        assert result.headers['cache-control'] == 'no-store'

def test_user_only_sees_own_requests_and_cannot_self_approve(roles):
    client, _, headers, _ = roles
    own = create(client, headers['normal_user'])
    create(client, headers['administrator'], 'https://example.org/other')
    rows = client.get('/api/access/requests', headers=headers['normal_user']).json()
    assert [r['id'] for r in rows] == [own['id']]
    assert review(client, headers['normal_user'], own).status_code == 403
    assert len(client.get('/api/access/requests', headers=headers['manager']).json()) == 2

@pytest.mark.parametrize('role',['head_administrator','administrator','manager'])
def test_each_reviewer_role_can_approve_a_normal_user(roles, role):
    client, _, headers, _ = roles
    request = create(client, headers['normal_user'])
    assert review(client, headers[role], request).status_code == 200

def test_managers_cannot_approve_their_own_request(roles):
    client, _, headers, _ = roles
    request = create(client, headers['manager'])
    assert review(client, headers['manager'], request).status_code == 403
    assert review(client, headers['administrator'], request).status_code == 200

def test_pending_and_rejected_destinations_stay_blocked(roles):
    client, _, h, _ = roles
    request = create(client, h['normal_user'])
    assert client.post('/api/access/check', headers=h['normal_user'],json={'target':URL}).json()['allowed'] is False
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).status_code == 403
    assert review(client,h['manager'],request,'reject').status_code == 200
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).status_code == 403

def test_one_visit_is_user_owned_and_consumed_exactly_once(roles):
    client, _, h, _ = roles
    request = create(client,h['normal_user'])
    assert review(client,h['manager'],request).status_code == 200
    assert client.post('/api/access/consume',headers=h['administrator'],json={'target':URL}).status_code == 403
    for _ in range(2):
        assert client.post('/api/access/check',headers=h['normal_user'],json={'target':URL}).json()['kind'] == 'once'
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).json()['kind'] == 'once'
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).status_code == 403

def test_concurrent_consumers_cannot_reuse_one_visit(roles):
    client, app, h, _ = roles
    request = create(client,h['normal_user'])
    review(client,h['manager'],request)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _:client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}),range(2)))
    assert sorted(r.status_code for r in responses) in ([200,403],[200,409])
    with app.state.session_factory() as db:
        assert len(list(db.scalars(select(GovernanceAudit).where(GovernanceAudit.action == 'once_consumed')))) == 1

def test_expired_once_and_pending_requests_cannot_be_used(roles):
    client, app, h, _ = roles
    request = create(client,h['normal_user'])
    review(client,h['manager'],request)
    with app.state.session_factory() as db:
        db.get(WebsiteRequest,request['id']).expires_at = utc_now()-timedelta(seconds=1)
        db.commit()
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).status_code == 403

def test_whitelist_is_reusable_exact_url_and_revocable(roles):
    client, _, h, _ = roles
    request=create(client,h['normal_user'])
    assert review(client,h['manager'],request,'whitelist').status_code == 200
    for role in ('normal_user','administrator','manager'):
        assert client.post('/api/access/consume',headers=h[role],json={'target':URL}).json()['kind'] == 'whitelist'
    for target in ['https://example.com/other','http://example.com/approved','https://example.com.evil/approved', 'https://example.com:8443/approved']:
        assert client.post('/api/access/check',headers=h['normal_user'],json={'target':target}).json()['allowed'] is False
    entry=client.get('/api/access/whitelist',headers=h['manager']).json()[0]
    assert client.post('/api/access/whitelist/'+entry['id']+'/revoke',headers=h['normal_user'],json={'reason':REASON}).status_code == 403
    assert client.post('/api/access/whitelist/'+entry['id']+'/revoke',headers=h['manager'],json={'reason':REASON}).status_code == 200
    assert client.post('/api/access/check',headers=h['normal_user'],json={'target':URL}).json()['allowed'] is False

def test_expired_whitelist_is_not_an_access_grant(roles):
    client, app, h, _=roles
    request=create(client,h['normal_user'])
    review(client,h['manager'],request,'whitelist')
    with app.state.session_factory() as db:
        entry=db.scalar(select(WebsiteWhitelist))
        entry.expires_at=utc_now()-timedelta(seconds=1)
        db.commit()
    assert client.get('/api/access/whitelist',headers=h['manager']).json() == []
    assert client.post('/api/access/consume',headers=h['normal_user'],json={'target':URL}).status_code == 403

def test_duplicate_requests_and_stale_reviews_do_not_duplicate_whitelist(roles):
    client, app, h, _=roles
    first=create(client,h['normal_user'])
    assert create(client,h['normal_user'])['id'] == first['id']
    assert review(client,h['manager'],first,'whitelist').status_code == 200
    assert review(client,h['administrator'],first,'whitelist').status_code == 409
    with app.state.session_factory() as db:
        assert len(list(db.scalars(select(WebsiteWhitelist)))) == 1


def test_renewed_whitelist_supersedes_the_previous_grant(roles):
    client, app, h, _ = roles
    first = create(client, h['normal_user'])
    assert review(client, h['manager'], first, 'whitelist').status_code == 200
    second = create(client, h['administrator'])
    assert review(client, h['head_administrator'], second, 'whitelist').status_code == 200
    entries = client.get('/api/access/whitelist', headers=h['manager']).json()
    assert len(entries) == 1
    with app.state.session_factory() as db:
        rows = list(db.scalars(select(WebsiteWhitelist)))
        assert len(rows) == 2  # Keep the original decision as historical evidence.
        assert sum(row.active for row in rows) == 1
    response = client.post('/api/access/whitelist/' + entries[0]['id'] + '/revoke',
        headers=h['manager'], json={'reason': REASON})
    assert response.status_code == 200
    assert client.post('/api/access/check', headers=h['normal_user'],
        json={'target': URL}).json()['allowed'] is False


def test_revocation_closes_legacy_duplicate_grants_for_the_same_url(roles):
    client, app, h, _ = roles
    request = create(client, h['normal_user'])
    assert review(client, h['manager'], request, 'whitelist').status_code == 200
    with app.state.session_factory() as db:
        original = db.scalar(select(WebsiteWhitelist))
        db.add(WebsiteWhitelist(target=URL, reviewer='administrator', reason=REASON,
            expires_at=utc_now() + timedelta(days=10)))
        db.commit()
        entry_id = original.id
    response = client.post('/api/access/whitelist/' + entry_id + '/revoke',
        headers=h['manager'], json={'reason': REASON})
    assert response.status_code == 200
    assert response.json()['revoked_entries'] == 2
    assert client.get('/api/access/whitelist', headers=h['manager']).json() == []
    assert client.post('/api/access/consume', headers=h['normal_user'],
        json={'target': URL}).status_code == 403
    with app.state.session_factory() as db:
        event = db.scalar(select(GovernanceAudit).where(GovernanceAudit.action == 'revoked'))
        assert event.details['revoked_entries'] == 2

def test_request_privacy_and_http_url_validation(roles):
    client, _, h, _=roles
    request=create(client,h['normal_user'],URL+'?secret=never-retained#fragment')
    assert request['target'] == URL
    assert 'secret' not in client.get('/api/access/requests',headers=h['manager']).text
    for target in ['javascript:alert(1)','file:///private','https://user:password@example.com/', 'https://example.com/path\\bad']:
        assert client.post('/api/access/requests',headers=h['normal_user'],json={'target':target,'reason':REASON}).status_code == 422
    assert client.post('/api/access/requests',headers=h['normal_user'],json={'target':URL,'reason':'        '}).status_code == 422
    assert client.post('/api/access/check',headers=h['normal_user'],json={'target':URL,'role':'administrator'}).status_code == 422

def test_requests_are_audited_and_throttled(roles):
    client, app, h, _=roles
    for i in range(20):create(client,h['normal_user'],f'https://example.com/{i}')
    assert client.post('/api/access/requests',headers=h['normal_user'],json={'target':URL,'reason':REASON}).status_code == 429
    with app.state.session_factory() as db:
        assert len(list(db.scalars(select(GovernanceAudit).where(GovernanceAudit.area == 'website_access')))) == 20
