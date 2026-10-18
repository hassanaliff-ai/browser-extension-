"""Approved device credentials can refresh only their own Chrome inventory."""
import pytest
from sqlalchemy import select,func
from alba_security.inventory import BrowserCredential,DeviceRegistration,DeviceEnrollment,digest
from alba_security.governance import GovernanceAudit
from tests.alba.test_threat_containment import system
from tests.alba.test_inventory import linked,SELF,OTHER

def publish(client,browser,items):
    return client.post('/api/device/inventory',headers={'X-ExtSecure-Device':browser['X-ExtSecure-Device']},json={'extensions':items})

def test_signed_out_device_uploads_enabled_and_disabled_extensions_without_other_device_access(system):
    client,_,headers,_=system;h=headers['hasan'];first,browser=linked(client,h);second,_=linked(client,h)
    result=publish(client,browser,[SELF,OTHER|{'enabled':False}])
    assert result.status_code==200,result.text
    assert result.json()['installed_count']==2 and result.json()['enabled_count']==1
    rows=client.get('/api/extensions',headers=h).json()
    assert len([r for r in rows if r['device_id']==first['id']])==2
    assert len([r for r in rows if r['device_id']==second['id']])==1
    assert next(r for r in rows if r['device_id']==first['id'] and r['extension_key']==OTHER['id'])['status']=='Disabled'
    assert next(r for r in client.get('/api/devices',headers=h).json() if r['id']==first['id'])['last_sync']
    assert client.get('/api/admin/me',headers={'X-ExtSecure-Device':browser['X-ExtSecure-Device']}).status_code==401

def test_complete_snapshot_marks_uninstalled_and_does_not_duplicate_unchanged_audits(system):
    client,app,h,_=system;_,browser=linked(client,h['hasan'])
    assert publish(client,browser,[SELF,OTHER]).status_code==200
    with app.state.session_factory() as db:before=db.scalar(select(func.count()).select_from(GovernanceAudit).where(GovernanceAudit.action=='chrome_inventory_synced'))
    assert publish(client,browser,[SELF,OTHER]).status_code==200
    with app.state.session_factory() as db:assert db.scalar(select(func.count()).select_from(GovernanceAudit).where(GovernanceAudit.action=='chrome_inventory_synced'))==before
    assert publish(client,browser,[SELF]).status_code==200
    rows=client.get('/api/extensions',headers=h['hasan']).json()
    assert next(r for r in rows if r['extension_key']==OTHER['id'])['status']=='Not installed'

@pytest.mark.parametrize('restriction',['blocked','pending','revoked','removed'])
def test_blocked_pending_revoked_or_removed_devices_cannot_upload(system,restriction):
    client,app,h,_=system;device,browser=linked(client,h['hasan'])
    from alba_security.models import Device
    with app.state.session_factory() as db:
        if restriction=='blocked':db.get(DeviceRegistration,device['id']).blocked=True
        elif restriction=='removed':db.get(Device,device['id']).inventory_removed=True
        elif restriction=='revoked':db.get(BrowserCredential,digest(browser['X-ExtSecure-Device'])).revoked=True
        else:
            enrollment=db.get(DeviceEnrollment,device['id'])
            if enrollment:enrollment.status='pending'
            else:db.add(DeviceEnrollment(device_id=device['id'],status='pending',requested_by='hasan',ip_source='Test'))
        db.commit()
    assert publish(client,browser,[SELF,OTHER]).status_code==403

def test_credentials_and_payload_validation_preserve_existing_inventory(system):
    client,_,h,_=system;device,browser=linked(client,h['hasan'])
    for header in ({},h['hasan'],{'X-ExtSecure-Device':'invalid'}):
        assert client.post('/api/device/inventory',headers=header,json={'extensions':[SELF]}).status_code==403
    for items in ([],[OTHER],[SELF|{'enabled':False}],[SELF,SELF]):
        assert publish(client,browser,items).status_code==422
    assert client.post('/api/device/inventory',headers=browser,json={'device_id':'someone-else','extensions':[SELF]}).status_code==422
    rows=client.get('/api/extensions',headers=h['hasan']).json()
    assert len(rows)==1 and rows[0]['installed']
