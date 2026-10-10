from datetime import timedelta
import pytest
from sqlalchemy import select
from alba_security.models import Scan, Alert, utc_now
from alba_security.governance import IncidentCase, CaseNote, GovernanceAudit
from alba_security.inventory import DeviceRegistration, BrowserCredential, digest
from tests.alba.test_governance import scan
from test_threat_containment import system
from tests.alba.test_roles import roles

def incident(client, headers):
    result=scan(client)
    cases=client.get('/api/cases',headers=headers).json()
    row=next(r for r in cases if r['scan_id']==result['id'])
    return result,client.get('/api/cases/'+row['id'],headers=headers).json()

def command(row, **extra):
    return {'expected_revision':row['revision'],'reason':'Reviewed incident evidence and recorded the decision','confirmed':True,**extra}

def test_removing_active_incident_preserves_block_scan_and_audit(system):
    client,app,headers,_=system;h=headers['hasan'];result,row=incident(client,h)
    row=client.post('/api/cases/'+row['id']+'/notes',headers=h,json={'body':'Original evidence has been reviewed.'}).json()
    response=client.post('/api/cases/'+row['id']+'/remove',headers=h,json=command(row))
    assert response.status_code==200,response.text
    assert response.json()['active_block_preserved']
    assert client.get('/api/cases/'+row['id'],headers=h).status_code==404
    assert client.get('/api/scans/'+result['id'],headers=h).status_code==200
    assert client.get('/api/threat-blocks',headers=h).json()[0]['active']
    with app.state.session_factory() as db:
        assert db.scalar(select(CaseNote.id).where(CaseNote.case_id==row['id'])) is None
        assert db.scalar(select(GovernanceAudit.id).where(GovernanceAudit.reference==row['id'],GovernanceAudit.action=='removed'))
    release=client.post('/api/threat-blocks/'+result['containment']['id']+'/release',headers=h,json=command(result['containment']))
    assert release.status_code==409
    recreated=client.post('/api/cases',headers=h,json={'scan_id':result['id'],'title':'Reopened containment investigation','assignee':'hasan'})
    assert recreated.status_code==201 and recreated.json()['id']!=row['id']

@pytest.mark.parametrize('status',['open','investigating','resolved'])
def test_any_incident_status_can_be_removed(system,status):
    client,_,headers,_=system;h=headers['hasan'];_,row=incident(client,h)
    for next_status in ([] if status=='open' else ['investigating'] if status=='investigating' else ['investigating','resolved']):
        row=client.post('/api/cases/'+row['id']+'/status',headers=h,json={'expected_revision':row['revision'],'status':next_status,'assignee':row['assignee'],'reason':'Reviewed original evidence and response'}).json()
    assert client.post('/api/cases/'+row['id']+'/remove',headers=h,json=command(row)).status_code==200

@pytest.mark.parametrize('confirmed',[False,1,'true'])
def test_remove_requires_explicit_boolean_confirmation(system,confirmed):
    client,_,headers,_=system;h=headers['hasan'];_,row=incident(client,h)
    assert client.post('/api/cases/'+row['id']+'/remove',headers=h,json=command(row,confirmed=confirmed)).status_code==422
    assert client.get('/api/cases/'+row['id'],headers=h).status_code==200

def test_new_note_prevents_stale_deletion(system):
    client,_,headers,_=system;h=headers['hasan'];_,row=incident(client,h)
    newer=client.post('/api/cases/'+row['id']+'/notes',headers=h,json={'body':'New evidence arrived during review.'}).json()
    assert newer['revision']>row['revision']
    assert client.post('/api/cases/'+row['id']+'/remove',headers=h,json=command(row)).status_code==409
    assert client.get('/api/cases/'+row['id'],headers=h).json()['notes']

def test_safety_review_is_audited_and_does_not_release_block(system):
    client,_,headers,_=system;h=headers['hasan'];result,row=incident(client,h)
    assert 'credentials_reviewed' in {a['code'] for a in row['safety_plan']['actions']}
    data={'expected_revision':row['revision'],'checks':['evidence_reviewed','user_notified'],'reason':'Reviewed evidence and informed the affected user'}
    saved=client.post('/api/cases/'+row['id']+'/safety',headers=h,json=data)
    assert saved.status_code==200,saved.text
    assert saved.json()['safety_plan']['recorded_by']=='hasan'
    assert saved.json()['containment']['active']
    assert saved.json()['status']=='open'
    assert client.post('/api/cases/'+row['id']+'/safety',headers=h,json=data).status_code==409

def test_irrelevant_or_duplicate_safety_checks_are_rejected(system):
    client,_,headers,_=system;h=headers['hasan'];_,row=incident(client,h)
    for checks in [[],['file_not_executed'],['user_notified','user_notified'],['invented']]:
        response=client.post('/api/cases/'+row['id']+'/safety',headers=h,json={'expected_revision':row['revision'],'checks':checks,'reason':'Reviewed incident-specific safety actions'})
        assert response.status_code==422

def test_incident_device_block_is_enforced_and_stale_device_changes_rollback(system):
    client,app,headers,_=system;h=headers['hasan'];_,row=incident(client,h)
    with app.state.session_factory() as db:
        db.add(DeviceRegistration(device_id=row['device_id'],ip_address='127.0.0.1',operating_system='Windows',added_by='hasan'))
        db.add(BrowserCredential(token_hash=digest('synthetic-device-token'),device_id=row['device_id']))
        db.commit()
    rejected=client.post('/api/cases/'+row['id']+'/block-device',headers=h,json=command(row,expected_device_revision=99))
    assert rejected.status_code==409
    assert client.get('/api/cases/'+row['id'],headers=h).json()['revision']==row['revision']
    blocked=client.post('/api/cases/'+row['id']+'/block-device',headers=h,json=command(row,expected_device_revision=1))
    assert blocked.status_code==200,blocked.text
    assert blocked.json()['device_protection']['blocked']
    device_headers={**h,'X-ExtSecure-Device':'synthetic-device-token'}
    assert client.get('/api/overview',headers=device_headers).status_code==403
    assert client.get('/api/inventory/self',headers=device_headers).status_code==200

def test_managers_can_record_safety_but_cannot_delete_or_block_devices(roles):
    client,_,headers,_=roles;_,row=incident(client,headers['head_administrator'])
    for action in ['remove','block-device']:
        assert client.post('/api/cases/'+row['id']+'/'+action,headers=headers['manager'],json=command(row,expected_device_revision=1) if action=='block-device' else command(row)).status_code==403
        assert client.post('/api/cases/'+row['id']+'/'+action,headers=headers['normal_user'],json={}).status_code==403
    saved=client.post('/api/cases/'+row['id']+'/safety',headers=headers['manager'],json={'expected_revision':row['revision'],'checks':['user_notified'],'reason':'Informed the affected user through approved channels'})
    assert saved.status_code==200

def test_deleted_incident_does_not_make_block_evidence_eligible_for_retention(system):
    client,app,headers,_=system;h=headers['hasan'];result,row=incident(client,h)
    assert client.post('/api/cases/'+row['id']+'/remove',headers=h,json=command(row)).status_code==200
    with app.state.session_factory() as db:
        db.get(Scan,result['id']).created_at=utc_now()-timedelta(days=1000)
        for alert in db.scalars(select(Alert).where(Alert.scan_id==result['id'])):alert.status='resolved'
        db.commit()
    assert client.get('/api/privacy/retention-preview',headers=h).json()['eligible_scans']==0
