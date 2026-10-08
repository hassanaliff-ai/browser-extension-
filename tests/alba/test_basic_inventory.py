"""Basic current-browser enrollment, retry guarantees and approval boundaries."""
import pytest
from sqlalchemy import select, func

from alba_security.inventory import BrowserCredential, DeviceEnrollment, DeviceRegistration, digest
from alba_security.models import Device
from alba_security.governance import GovernanceAudit
from tests.alba.test_governance import system  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401
from tests.alba.test_inventory import SELF, block

KEY = 'c'*64


def connect(client, headers, **changes):
    return client.post('/api/inventory/connect', headers=headers, json={
        'browser_token':KEY, 'operating_system':'Windows', 'extension':SELF, 'initial_access':'trusted', **changes})


@pytest.mark.parametrize('role', ['head_administrator','administrator','manager','normal_user'])
def test_account_role_controls_immediate_connection_or_pending_approval(roles, role):
    client, app, headers, _ = roles
    response = connect(client, headers[role])
    assert response.status_code == 200, response.text
    row = response.json()
    approved = role in {'head_administrator','administrator'}
    assert row['pending'] is not approved and row['blocked'] is False
    assert row['status'] == ('Active' if approved else 'Pending approval')
    assert row['trusted'] is approved
    assert row['operating_system']=='Windows' and row['linked']
    assert row['ip_address'] is None  # A test peer or localhost is not a LAN IP.
    assert 'browser_token' not in row and 'pairing_code' not in row and KEY not in str(row)
    browser={**headers[role],'X-ExtSecure-Device':KEY}
    check=client.post('/api/access/check', headers=browser, json={'target':'https://example.com/'})
    assert check.status_code == (200 if approved else 403)
    with app.state.session_factory() as db:
        assert db.get(BrowserCredential,digest(KEY)).device_id==row['device_id']
        assert db.get(DeviceEnrollment,row['device_id']).status==('approved' if approved else 'pending')


def test_repeated_clicks_and_lost_response_retries_create_exactly_one_device(system):
    client, app, headers, _ = system
    first=connect(client,headers['hasan']).json()
    second=connect(client,headers['hasan']).json()
    third=connect(client,{**headers['hasan'],'X-ExtSecure-Device':KEY}).json()
    assert first['device_id']==second['device_id']==third['device_id']
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(Device))==1
        assert db.scalar(select(func.count()).select_from(BrowserCredential))==1


def test_pending_device_can_be_approved_then_sync_but_cannot_approve_itself(roles):
    client, _, headers, _ = roles
    device=connect(client,headers['normal_user']).json()
    browser={**headers['normal_user'],'X-ExtSecure-Device':KEY}
    assert connect(client,browser).json()['pending'] is True
    assert client.post('/api/inventory/sync', headers=browser, json={'extensions':[SELF]}).status_code==403
    path='/api/inventory/devices/'+device['device_id']+'/status'
    decision={'blocked':False,'expected_revision':device['revision'],'reason':'Administrator verified this device owner'}
    assert client.post(path,headers=browser,json=decision).status_code==403
    assert client.post(path,headers=headers['head_administrator'],json=decision).status_code==200
    assert connect(client,browser).json()['status']=='Active'
    assert client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF]}).status_code==200


def test_rejected_and_blocked_devices_stay_blocked_on_reconnection(roles):
    client, _, headers, _ = roles
    device=connect(client,headers['normal_user']).json()
    browser={**headers['normal_user'],'X-ExtSecure-Device':KEY}
    assert block(client,headers['head_administrator'],{'id':device['device_id']}).status_code==200
    retry=connect(client,browser).json()
    assert retry['blocked'] is True and retry['pending'] is False
    assert client.post('/api/access/consume',headers=browser,json={'target':'https://example.com/'}).status_code==403
    # Deleting local storage yields another pending request, never active access.
    fresh=connect(client,headers['normal_user'],browser_token='d'*64).json()
    assert fresh['pending'] and fresh['device_id']!=device['device_id']


def test_administrator_retry_is_not_an_implicit_unblock(system):
    client, _, headers, _ = system
    device=connect(client,headers['hasan']).json()
    browser={**headers['hasan'],'X-ExtSecure-Device':KEY}
    block(client,headers['hasan'],{'id':device['device_id']})
    assert connect(client,browser).json()['blocked'] is True
    assert client.get('/api/overview',headers=browser).status_code==403


def test_optional_name_and_ip_are_saved_and_empty_refresh_preserves_them(system):
    client, _, headers, _ = system
    first=connect(client,headers['hasan'],name='Office laptop',ip_address='192.168.10.4').json()
    second=connect(client,{**headers['hasan'],'X-ExtSecure-Device':KEY}).json()
    assert first['device_name']==second['device_name']=='Office laptop'
    assert second['ip_address']=='192.168.10.4' and second['ip_source']=='Entered IP'


@pytest.mark.parametrize('changes', [{'ip_address':'bad IP'}, {'operating_system':'FakeOS'},
    {'browser_token':'guess'}, {'name':' '}, {'approved':True}])
def test_invalid_or_client_owned_approval_fields_are_rejected(system,changes):
    client, _, headers, _ = system
    assert connect(client,headers['hasan'],**changes).status_code==422
    assert client.get('/api/devices',headers=headers['hasan']).json()==[]


def test_anonymous_enrollment_is_rejected(system):
    client, _, _, _ = system
    assert connect(client,{}).status_code==401


def test_revoked_credentials_cannot_be_silently_reactivated(system):
    client, app, headers, _ = system
    connect(client,headers['hasan'])
    with app.state.session_factory() as db:
        db.get(BrowserCredential,digest(KEY)).revoked=True
        db.commit()
    assert connect(client,headers['hasan']).status_code==403


def test_header_and_connect_key_must_describe_the_same_profile(system):
    client, _, headers, _ = system
    connect(client,headers['hasan'])
    assert connect(client,{**headers['hasan'],'X-ExtSecure-Device':KEY},browser_token='d'*64).status_code==409


def test_optional_metadata_updates_are_audited_and_invalidate_stale_admin_decisions(system):
    client, app, headers, _ = system
    first=connect(client,headers['hasan']).json()
    updated=connect(client,{**headers['hasan'],'X-ExtSecure-Device':KEY},name='Renamed device',ip_address='192.168.1.90').json()
    assert updated['revision']==first['revision']+1
    result=client.post('/api/inventory/devices/'+first['device_id']+'/status',headers=headers['hasan'],
        json={'blocked':True,'expected_revision':first['revision'],'reason':'A stale review must be refreshed before blocking'})
    assert result.status_code==409
    with app.state.session_factory() as db:
        entry=db.scalar(select(GovernanceAudit).where(GovernanceAudit.action=='device_details_updated'))
        assert set(entry.details['fields'])=={'name','ip_address'}
        assert '192.168.1.90' not in str(entry.details)


@pytest.mark.parametrize('role', ['head_administrator','administrator','manager','normal_user'])
def test_blocked_choice_is_saved_before_activity_for_every_role(roles, role):
    client, app, headers, _ = roles
    response=connect(client,headers[role],initial_access='blocked')
    assert response.status_code==200,response.text
    row=response.json()
    assert row['blocked'] is True and row['pending'] is False and row['trusted'] is False
    assert row['status']=='Blocked' and row['linked']
    browser={**headers[role],'X-ExtSecure-Device':KEY}
    assert client.post('/api/access/check',headers=browser,json={'target':'https://example.com/'}).status_code==403
    assert client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF]}).status_code==403
    assert client.get('/api/admin/me',headers=browser).json()['inventory']['blocked'] is True
    assert connect(client,browser,initial_access='trusted').json()['blocked'] is True
    with app.state.session_factory() as db:
        assert db.get(DeviceEnrollment,row['device_id']).status=='blocked'
        entry=db.scalar(select(GovernanceAudit).where(GovernanceAudit.action=='device_added_blocked'))
        assert entry.details['initial_access']=='blocked' and KEY not in str(entry.details)


@pytest.mark.parametrize('choice',[None,'','approved','forever',True])
def test_new_registration_requires_a_valid_explicit_access_choice(system,choice):
    client, _, headers, _ = system
    assert connect(client,headers['hasan'],initial_access=choice).status_code==422
    assert client.get('/api/devices',headers=headers['hasan']).json()==[]


def test_omitting_access_choice_for_new_registration_is_rejected(system):
    client, _, headers, _ = system
    response=client.post('/api/inventory/connect',headers=headers['hasan'],json={
        'browser_token':KEY,'operating_system':'Windows','extension':SELF})
    assert response.status_code==422
    assert 'Choose Trusted device or Blocked device' in response.text


def test_only_admin_can_allow_a_device_added_as_blocked(roles):
    client, app, headers, _ = roles
    device=connect(client,headers['normal_user'],initial_access='blocked').json()
    browser={**headers['normal_user'],'X-ExtSecure-Device':KEY}
    path='/api/inventory/devices/'+device['device_id']+'/status'
    decision={'blocked':False,'expected_revision':device['revision'],'reason':'Administrator verified and allowed the blocked device'}
    assert client.post(path,headers=browser,json=decision).status_code==403
    allowed=client.post(path,headers=headers['head_administrator'],json=decision)
    assert allowed.status_code==200 and allowed.json()['trusted'] is True
    assert client.post('/api/access/check',headers=browser,json={'target':'https://example.com/'}).status_code==200
    with app.state.session_factory() as db:
        assert db.get(DeviceEnrollment,device['device_id']).status=='approved'


def test_refresh_needs_no_initial_choice_and_cannot_change_existing_trust(system):
    client, _, headers, _ = system
    device=connect(client,headers['hasan']).json()
    browser={**headers['hasan'],'X-ExtSecure-Device':KEY}
    refreshed=connect(client,browser,initial_access=None).json()
    assert refreshed['device_id']==device['device_id'] and refreshed['trusted'] is True
    retry=connect(client,browser,initial_access='blocked').json()
    assert retry['trusted'] is True  # Status changes require the reviewed status endpoint.
