import pytest
from tests.alba.test_threat_containment import system
from tests.alba.test_roles import roles
from tests.alba.test_inventory import linked,SELF,OTHER

def setup(client,headers):
    device,browser=linked(client,headers)
    assert client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF,{**OTHER,'enabled':False}]}).status_code==200
    rows=client.get('/api/extensions',headers=browser).json()
    return device,browser,next(r for r in rows if r['extension_key']==OTHER['id'])

def decide(client,headers,row,desired='blocked',revision=0,confirmed=True):
    return client.post('/api/inventory/extensions/'+row['id']+'/control',headers=headers,json={'desired':desired,'expected_revision':revision,'confirmed':confirmed,'reason':'Administrator reviewed extension and target device'})

def test_disabled_inventory_and_block_receipt_lifecycle(system):
    client,app,headers,_=system;device,browser,row=setup(client,headers['hasan'])
    assert row['status']=='Disabled' and row['installed'] and not row['enabled']
    result=decide(client,headers['hasan'],row);assert result.status_code==200,result.text
    command=client.get('/api/inventory/extension-controls',headers=browser).json()[0]
    assert command['chrome_id']==OTHER['id'] and command['desired']=='blocked'
    url='/api/inventory/extensions/'+row['id']+'/receipt'
    assert client.post(url,headers=browser,json={'revision':1,'status':'applied'}).status_code==200
    assert client.get('/api/inventory/extension-controls',headers=browser).json()[0]['desired']=='blocked'
    assert decide(client,headers['hasan'],row,'enabled',1).status_code==200
    assert client.post(url,headers=browser,json={'revision':1,'status':'applied'}).status_code==409
    assert client.post(url,headers=browser,json={'revision':2,'status':'applied'}).status_code==200
    assert client.get('/api/inventory/extension-controls',headers=browser).json()==[]

def test_device_scoped_commands_and_receipts(system):
    client,_,headers,_=system;_,first,row=setup(client,headers['hasan']);_,second,_=setup(client,headers['hasan'])
    assert decide(client,headers['hasan'],row).status_code==200
    assert client.get('/api/inventory/extension-controls',headers=second).json()==[]
    assert client.post('/api/inventory/extensions/'+row['id']+'/receipt',headers=second,json={'revision':1,'status':'applied'}).status_code==404
    assert client.get('/api/inventory/extension-controls',headers=headers['hasan']).status_code==403

@pytest.mark.parametrize('role',['head_administrator','administrator','manager','normal_user'])
def test_only_administrators_issue_extension_actions(roles,role):
    client,_,headers,_=roles;_,browser,row=setup(client,headers['head_administrator'])
    assert decide(client,headers[role],row).status_code==(200 if role in {'head_administrator','administrator'} else 403)

def test_self_protection_confirmation_and_stale_revision(system):
    client,_,headers,_=system;_,browser,row=setup(client,headers['hasan'])
    selfrow=next(r for r in client.get('/api/extensions',headers=browser).json() if r['extension_key']==SELF['id'])
    assert selfrow['protected']
    for action in ['enabled','disabled','blocked','removed']:assert decide(client,headers['hasan'],selfrow,action).status_code==409
    assert decide(client,headers['hasan'],row,confirmed=False).status_code==422
    assert decide(client,headers['hasan'],row).status_code==200
    assert decide(client,headers['hasan'],row,'enabled').status_code==409

def test_restricted_extensions_and_missing_snapshot(system):
    client,_,headers,_=system;_,browser,row=setup(client,headers['hasan'])
    client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF,{**OTHER,'may_disable':False,'may_enable':False}]})
    assert decide(client,headers['hasan'],row).status_code==409
    assert decide(client,headers['hasan'],row,'enabled').status_code==409
    client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF]})
    assert decide(client,headers['hasan'],row,'removed').status_code==409

def test_remove_retains_inventory_history_and_audit(system):
    client,_,headers,_=system;_,browser,row=setup(client,headers['hasan'])
    assert decide(client,headers['hasan'],row,'removed').status_code==200
    client.post('/api/inventory/extensions/'+row['id']+'/receipt',headers=browser,json={'revision':1,'status':'applied'})
    client.post('/api/inventory/sync',headers=browser,json={'extensions':[SELF]})
    removed=next(r for r in client.get('/api/extensions',headers=browser).json() if r['id']==row['id'])
    assert removed['status']=='Not installed' and removed['control']['status']=='applied'
    audit=client.get('/api/governance/audit',headers=browser).json()
    assert any(r['action']=='extension_control_requested' for r in audit)

def test_receipts_reject_false_success_or_failure_without_reason(system):
    client,_,headers,_=system;_,browser,row=setup(client,headers['hasan'])
    assert decide(client,headers['hasan'],row).status_code==200
    url='/api/inventory/extensions/'+row['id']+'/receipt'
    for payload in [{'revision':1,'status':'applied','error':'chrome_restricted'},{'revision':1,'status':'failed'}]:
        assert client.post(url,headers=browser,json=payload).status_code==422
