import pytest
from sqlalchemy import select,func
from tests.alba.test_threat_containment import system
from tests.alba.test_roles import roles
from tests.alba.test_inventory import linked,SELF,OTHER
from tests.alba.test_governance import scan,INGEST
from alba_security.models import Device,Extension,Scan
from alba_security.inventory import BrowserCredential

def inventory(client,headers):
    device,browser=linked(client,headers)
    assert client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF,OTHER]}).status_code==200
    return device,browser,client.get('/api/extensions',headers=browser).json()

def remove(client,headers,kind,row,**changes):
    return client.post('/api/inventory/'+kind+'/'+row['id']+'/remove',headers=headers,json={'expected_revision':row.get('inventory_revision',1),'confirmed':True,'reason':'Administrator reviewed inventory removal request',**changes})

def test_any_extension_including_extsecure_can_be_removed_from_inventory_and_restored(system):
    client,app,headers,_=system;device,browser,rows=inventory(client,headers['hasan'])
    for row in rows:
        result=remove(client,headers['hasan'],'extensions',row);assert result.status_code==200,result.text
        assert result.json()['uninstalled'] is False
    assert all(r['inventory_removed'] for r in client.get('/api/extensions',headers=browser).json())
    assert client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF,OTHER]}).status_code==200
    assert all(r['inventory_removed'] for r in client.get('/api/extensions',headers=browser).json())
    row=client.get('/api/extensions',headers=browser).json()[0]
    assert client.post('/api/inventory/extensions/'+row['id']+'/restore',headers=headers['hasan'],json={'expected_revision':row['inventory_revision'],'confirmed':True,'reason':'Return approved extension to active inventory'}).status_code==200
    assert not next(r for r in client.get('/api/extensions',headers=browser).json() if r['id']==row['id'])['inventory_removed']

def test_remove_device_revokes_credentials_archives_extensions_and_rejects_old_connection(system):
    client,app,headers,_=system;device,browser,rows=inventory(client,headers['hasan'])
    result=remove(client,headers['hasan'],'devices',device);assert result.status_code==200,result.text
    assert result.json()['extensions_removed']==2
    assert client.get('/api/inventory/self',headers=browser).json()['removed']
    assert client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF]}).status_code==403
    assert client.get('/api/inventory/extension-controls',headers=browser).status_code==403
    with app.state.session_factory() as db:
        assert all(r.revoked for r in db.scalars(select(BrowserCredential)))
        assert db.get(Device,device['id']).inventory_removed
        assert all(r.inventory_removed for r in db.scalars(select(Extension)))
    assert client.post('/api/inventory/devices/'+device['id']+'/status',headers=headers['hasan'],json={'blocked':False,'expected_revision':2,'reason':'Try to reopen a removed device'}).status_code==409
    assert client.post('/api/inventory/devices/'+device['id']+'/pairing-code',headers=headers['hasan'],json={'expected_revision':2,'reason':'Try to reuse a removed connection'}).status_code==409
    assert client.post('/api/inventory/extensions/'+rows[0]['id']+'/restore',headers=headers['hasan'],json={'expected_revision':2,'confirmed':True,'reason':'Try restoring removed device extension'}).status_code==409

@pytest.mark.parametrize('kind',['devices','extensions'])
@pytest.mark.parametrize('role',['head_administrator','administrator','manager','normal_user'])
def test_removal_is_administrator_only(roles,kind,role):
    client,_,headers,_=roles;device,browser,rows=inventory(client,headers['head_administrator']);row=device if kind=='devices' else rows[0]
    assert remove(client,headers[role],kind,row).status_code==(200 if role in {'head_administrator','administrator'} else 403)

def test_confirmation_revision_and_repeat_remove_are_checked(system):
    client,_,headers,_=system;device,browser,rows=inventory(client,headers['hasan'])
    for kind,row in [('devices',device),('extensions',rows[0])]:
        assert remove(client,headers['hasan'],kind,row,confirmed=False).status_code==422
        assert remove(client,headers['hasan'],kind,row,expected_revision=99).status_code==409
    assert remove(client,headers['hasan'],'extensions',rows[0]).status_code==200
    assert remove(client,headers['hasan'],'extensions',rows[0]).status_code==409

def test_legacy_scan_records_can_be_removed_without_deleting_evidence(system):
    client,app,headers,_=system
    payload={'device_id':'legacy-removal-device','device_name':'Legacy test device','target_kind':'url','target':'https://example.com/','signals':[]}
    result=client.post('/api/scans',headers=INGEST,json=payload);assert result.status_code==201
    old=client.get('/api/devices',headers=headers['hasan']).json()[0]
    assert remove(client,headers['hasan'],'devices',old).status_code==200
    with app.state.session_factory() as db:assert db.scalar(select(func.count(Scan.id)))==1
    assert client.get('/api/scans',headers=headers['hasan']).json()[0]['id']==result.json()['id']
    assert client.post('/api/scans',headers=INGEST,json=payload).status_code==403
