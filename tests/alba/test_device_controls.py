"""Higher approvers issue device controls without a recipient account session."""
from concurrent.futures import ThreadPoolExecutor
import time
import pytest
from tests.alba.test_extension_controls import setup,decide
from tests.alba.test_roles import roles
from tests.alba.test_threat_containment import system
from alba_security.inventory import DeviceRegistration,BrowserCredential,digest

@pytest.mark.parametrize('owner',['head_administrator','administrator','manager','normal_user'])
@pytest.mark.parametrize('actor',['head_administrator','administrator','manager','normal_user'])
def test_control_role_hierarchy(roles,owner,actor):
    client,app,headers,_=roles
    device,browser,row=setup(client,headers['head_administrator'])
    with app.state.session_factory() as db:
        db.get(DeviceRegistration,device['id']).added_by='hasan' if owner=='head_administrator' else owner
        db.commit()
    levels={'normal_user':0,'manager':1,'administrator':2,'head_administrator':3}
    permitted=actor!='normal_user' and levels[actor]>=levels[owner]
    actor_headers={**headers[actor],**device_headers(browser)}
    response=client.get('/api/extensions',headers=actor_headers)
    if actor=='normal_user':assert response.status_code==403
    else:assert next(r for r in response.json() if r['id']==row['id'])['can_control']==permitted
    assert decide(client,actor_headers,row).status_code==(200 if permitted else 403)

def test_manager_cannot_uninstall_lower_user_extension(roles):
    client,app,headers,_=roles;device,browser,row=setup(client,headers['head_administrator'])
    with app.state.session_factory() as db:
        db.get(DeviceRegistration,device['id']).added_by='normal_user';db.commit()
    assert decide(client,{**headers['manager'],**device_headers(browser)},row,'removed').status_code==403

def device_headers(browser):return {'X-ExtSecure-Device':browser['X-ExtSecure-Device']}

def test_signed_out_device_delivery_and_receipt(system):
    client,_,headers,_=system;_,browser,row=setup(client,headers['hasan']);token=device_headers(browser)
    assert decide(client,headers['hasan'],row).status_code==200
    batch=client.get('/api/device/extension-controls',headers=token).json()
    assert batch['commands'][0]['extension_id']==row['id']
    url='/api/device/extensions/'+row['id']+'/receipt'
    assert client.post(url,headers=token,json={'revision':1,'status':'applied'}).status_code==200
    assert decide(client,headers['hasan'],row,'enabled',1).status_code==200
    assert client.post(url,headers=token,json={'revision':1,'status':'applied'}).status_code==409
    assert client.post(url,headers=token,json={'revision':2,'status':'applied'}).status_code==200
    assert client.get('/api/device/extension-controls',headers=token).json()['commands']==[]
    observed=next(r for r in client.get('/api/extensions',headers=headers['hasan']).json() if r['id']==row['id'])
    assert observed['enabled'] and observed['status']=='Enabled'

def test_peer_administrator_cannot_control_another_administrator(roles):
    client,app,headers,_=roles;device,browser,row=setup(client,headers['head_administrator'])
    with app.state.session_factory() as db:
        db.get(DeviceRegistration,device['id']).added_by='reviewer';db.commit()
    assert decide(client,headers['administrator'],row).status_code==403

def test_pending_devices_denied_and_approved_blocked_device_keeps_safety_channel(system):
    from alba_security.inventory import DeviceEnrollment
    client,app,headers,_=system;device,browser,row=setup(client,headers['hasan']);token=device_headers(browser)
    with app.state.session_factory() as db:
        db.add(DeviceEnrollment(device_id=device['id'],status='pending',requested_by='hasan',ip_source='Test'));db.commit()
    assert client.get('/api/device/extension-controls',headers=token).status_code==403
    with app.state.session_factory() as db:
        db.get(DeviceEnrollment,device['id']).status='approved'
        db.get(DeviceRegistration,device['id']).blocked=True;db.commit()
    assert decide(client,headers['hasan'],row).status_code==200
    assert client.get('/api/device/extension-controls',headers=token).json()['commands'][0]['desired']=='blocked'

def test_device_channel_denies_cross_device_and_revoked_tokens(system):
    client,app,headers,_=system;_,first,row=setup(client,headers['hasan']);_,second,_=setup(client,headers['hasan'])
    assert decide(client,headers['hasan'],row).status_code==200
    assert client.get('/api/device/extension-controls').status_code==403
    assert client.get('/api/device/extension-controls',headers=device_headers(second)).json()['commands']==[]
    assert client.post('/api/device/extensions/'+row['id']+'/receipt',headers=device_headers(second),json={'revision':1,'status':'applied'}).status_code==404
    with app.state.session_factory() as db:
        db.get(BrowserCredential,digest(first['X-ExtSecure-Device'])).revoked=True;db.commit()
    assert client.get('/api/device/extension-controls',headers=device_headers(first)).status_code==403

def test_new_decision_wakes_waiting_device_without_user_approval(system):
    client,_,headers,_=system;_,browser,row=setup(client,headers['hasan'])
    token=device_headers(browser);cursor=client.get('/api/device/extension-controls',headers=token).json()['cursor']
    with ThreadPoolExecutor() as pool:
        pending=pool.submit(client.get,'/api/device/extension-controls?cursor='+str(cursor),headers=token)
        time.sleep(.3)
        assert not pending.done()
        start=time.monotonic();assert decide(client,headers['hasan'],row).status_code==200
        response=pending.result(timeout=3)
        assert time.monotonic()-start<3 and response.json()['commands'][0]['desired']=='blocked'
