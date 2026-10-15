from datetime import timedelta
import pytest
from alba_security.inventory import DeviceRegistration,BrowserCredential,DeviceEnrollment,digest
from alba_security.models import Device,utc_now
from tests.alba.test_threat_containment import system
from tests.alba.test_inventory import linked

def row(client,headers,device):return next(r for r in client.get('/api/devices',headers=headers).json() if r['id']==device['id'])
def pulse(client,browser):return client.post('/api/device/heartbeat',headers={'X-ExtSecure-Device':browser['X-ExtSecure-Device']})

def test_pairing_is_not_online_evidence_and_heartbeat_needs_no_account_session(system):
    client,app,headers,_=system;device,browser=linked(client,headers['hasan'])
    assert row(client,headers['hasan'],device)['status']=='Offline'
    response=pulse(client,browser);assert response.status_code==200
    data=row(client,headers['hasan'],device)
    assert data['status']=='Active' and data['online'] and data['last_heartbeat']
    assert data['access_status']=='Trusted' and data['heartbeat_timeout_seconds']==90

@pytest.mark.parametrize('age,expected',[(-10,'Offline'),(89,'Active'),(91,'Offline'),(3600,'Offline')])
def test_connection_expires_using_server_time(system,age,expected):
    client,app,headers,_=system;device,browser=linked(client,headers['hasan'])
    with app.state.session_factory() as db:
        db.get(DeviceRegistration,device['id']).last_heartbeat=utc_now()-timedelta(seconds=age)
        db.get(Device,device['id']).last_seen=utc_now();db.commit()
    assert row(client,headers['hasan'],device)['status']==expected

@pytest.mark.parametrize('access',['blocked','pending'])
def test_access_policy_is_separate_and_pulses_never_unblock_devices(system,access):
    client,app,headers,_=system;device,browser=linked(client,headers['hasan'])
    with app.state.session_factory() as db:
        db.get(DeviceRegistration,device['id']).blocked=True
        if access=='pending':db.add(DeviceEnrollment(device_id=device['id'],status='pending',requested_by='hasan',ip_source='Test'))
        db.commit()
    assert pulse(client,browser).status_code==200
    data=row(client,headers['hasan'],device)
    assert data['status']=='Active' and data['access_status']==('Blocked' if access=='blocked' else 'Pending approval')
    assert client.get('/api/overview',headers=browser).status_code==403

def test_unknown_or_revoked_credentials_cannot_fake_presence(system):
    client,app,headers,_=system;device,browser=linked(client,headers['hasan'])
    assert client.post('/api/device/heartbeat').status_code==403
    assert client.post('/api/device/heartbeat',headers=headers['hasan']).status_code==403
    with app.state.session_factory() as db:
        db.get(BrowserCredential,digest(browser['X-ExtSecure-Device'])).revoked=True;db.commit()
    assert pulse(client,browser).status_code==403
    assert row(client,headers['hasan'],device)['online'] is False

def test_removed_device_cannot_send_presence(system):
    client,app,headers,_=system;device,browser=linked(client,headers['hasan'])
    with app.state.session_factory() as db:
        db.get(Device,device['id']).inventory_removed=True;db.commit()
    assert pulse(client,browser).status_code==403

def test_heartbeat_only_updates_its_paired_device(system):
    client,_,headers,_=system;first,browser=linked(client,headers['hasan']);second,_=linked(client,headers['hasan'])
    assert pulse(client,browser).status_code==200
    assert row(client,headers['hasan'],first)['online'] and not row(client,headers['hasan'],second)['online']

def test_existing_device_control_poll_is_also_verified_presence(system):
    client,_,headers,_=system;device,browser=linked(client,headers['hasan'])
    assert row(client,headers['hasan'],device)['status']=='Offline'
    response=client.get('/api/device/extension-controls',headers={'X-ExtSecure-Device':browser['X-ExtSecure-Device']})
    assert response.status_code==200 and row(client,headers['hasan'],device)['status']=='Active'
