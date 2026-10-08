"""Acknowledgement is required before either approval or rejection is recorded."""
import pytest
from sqlalchemy import select
from alba_security.website_access import WebsiteRequest, WebsiteWhitelist
from alba_security.governance import GovernanceAudit
from tests.alba.test_governance import system  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401
from tests.alba.test_website_access import create, REASON


@pytest.mark.parametrize('decision',['temporary','whitelist','reject'])
def test_api_confirmation_is_mandatory_and_failure_has_no_side_effects(roles,decision):
    client,app,h,_=roles
    request=create(client,h['head_administrator'])
    body={'decision':decision,'expected_revision':request['revision'],'reason':REASON,
          'duration_hours':24,'whitelist_forever':decision=='whitelist'}
    path='/api/access/requests/'+request['id']+'/review'
    for payload in [body,*[{**body,'confirmed':value} for value in (False,'true',1,None)]]:
        assert client.post(path,headers=h['head_administrator'],json=payload).status_code==422
        with app.state.session_factory() as db:
            row=db.get(WebsiteRequest,request['id'])
            assert row.status=='pending' and row.revision==1
            assert not list(db.scalars(select(WebsiteWhitelist)))
            assert not list(db.scalars(select(GovernanceAudit).where(GovernanceAudit.action.in_(['approved','rejected']))))
    response=client.post(path,headers=h['head_administrator'],json={**body,'confirmed':True})
    assert response.status_code==200,response.text
    with app.state.session_factory() as db:
        audit=db.scalar(select(GovernanceAudit).where(GovernanceAudit.reference==request['id'],GovernanceAudit.action.in_(['approved','rejected'])))
        assert audit.details['confirmed'] is True
