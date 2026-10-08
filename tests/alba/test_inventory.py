"""Real sessions, device enrollment, inventory lifecycle and access enforcement."""
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from alba_security.inventory import BrowserCredential, DeviceRegistration, ChromeObservation, digest
from alba_security.models import Device, Extension, PersonalScan, Scan, utc_now
from alba_security.governance import GovernanceAudit
from tests.alba.test_governance import system, INGEST  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401

SELF = {'id': 'a'*32, 'name': 'ExtSecure', 'version': '0.7.0'}
OTHER = {'id': 'b'*32, 'name': 'Second Chrome extension', 'version': '1.2'}


def add(client, headers, **changes):
    data = {'name': 'Hasan workstation', 'ip_address': '192.168.1.25',
            'operating_system': 'Windows', 'reason': 'Register the authorized Chrome workstation'}
    response = client.post('/api/inventory/devices', headers=headers, json={**data, **changes})
    return response


def pair(client, headers, code):
    return client.post('/api/inventory/pair', headers=headers,
        json={'code': code, 'extension': SELF, 'operating_system': 'Windows'})


def linked(client, headers):
    device = add(client, headers).json()
    response = pair(client, headers, device['pairing_code'])
    assert response.status_code == 200, response.text
    return device, {**headers, 'X-ExtSecure-Device': response.json()['device_token']}


def block(client, headers, device, blocked=True):
    row = next(row for row in client.get('/api/devices', headers=headers).json() if row['id'] == device['id'])
    return client.post('/api/inventory/devices/'+row['id']+'/status', headers=headers,
        json={'blocked': blocked, 'expected_revision': row['revision'], 'reason': 'Device access reviewed by administrator'})


@pytest.mark.parametrize('role', ['head_administrator', 'administrator', 'manager', 'normal_user'])
def test_only_administrators_can_register_devices(roles, role):
    client, _, headers, _ = roles
    assert add(client, headers[role]).status_code == (201 if role in {'head_administrator','administrator'} else 403)


@pytest.mark.parametrize('changes', [
    {'ip_address':'not an ip'}, {'ip_address':'0.0.0.0'}, {'ip_address':'224.0.0.1'},
    {'operating_system':'invented OS'}, {'name':'  '}, {'reason':'        '},
])
def test_invalid_device_metadata_is_rejected(system, changes):
    client, _, headers, _ = system
    assert add(client, headers['hasan'], **changes).status_code == 422
    assert client.get('/api/devices', headers=headers['hasan']).json() == []


def test_ipv6_and_registration_enable_enrollment_without_exposing_secrets(system):
    client, app, headers, _ = system
    device = add(client, headers['hasan'], ip_address='2001:db8:0:0::1').json()
    assert device['ip_address'] == '2001:db8::1'
    rows = client.get('/api/devices', headers=headers['hasan']).json()
    assert rows[0]['status'] == 'Awaiting pairing'
    assert 'pairing_code' not in rows[0]
    assert client.get('/api/admin/me', headers=headers['hasan']).json()['inventory']['enrollment_required']
    assert client.get('/api/overview', headers=headers['hasan']).status_code == 403
    with app.state.session_factory() as db:
        row = db.get(DeviceRegistration, device['id'])
        assert row.pairing_hash == digest(device['pairing_code'])
        assert device['pairing_code'] not in str(row.__dict__)


def test_pairing_is_one_time_and_token_is_hashed(system):
    client, app, headers, _ = system
    device, browser = linked(client, headers['hasan'])
    assert pair(client, headers['hasan'], device['pairing_code']).status_code == 403
    assert client.get('/api/overview', headers=browser).status_code == 200
    with app.state.session_factory() as db:
        token = browser['X-ExtSecure-Device']
        assert db.get(BrowserCredential, digest(token)).device_id == device['id']
        assert db.get(BrowserCredential, token) is None
    profile = client.get('/api/admin/me', headers=browser).json()
    assert profile['inventory']['linked'] and token not in str(profile)


def test_expired_code_and_blocked_device_cannot_pair(system):
    client, app, headers, _ = system
    device = add(client, headers['hasan']).json()
    with app.state.session_factory() as db:
        db.get(DeviceRegistration, device['id']).pairing_expires = utc_now()-timedelta(seconds=1)
        db.commit()
    assert pair(client, headers['hasan'], device['pairing_code']).status_code == 403
    assert block(client, headers['hasan'], device).status_code == 200
    assert pair(client, headers['hasan'], device['pairing_code']).status_code == 403


def test_repairing_revokes_previous_browser_and_old_codes(system):
    client, _, headers, _ = system
    device, first = linked(client, headers['hasan'])
    row = client.get('/api/devices', headers=headers['hasan']).json()[0]
    code = client.post('/api/inventory/devices/'+device['id']+'/pairing-code', headers=headers['hasan'],
        json={'expected_revision':row['revision'], 'reason':'Replace the previous authorized Chrome profile'}).json()
    second = pair(client, headers['hasan'], code['pairing_code'])
    assert second.status_code == 200
    assert client.get('/api/overview', headers=first).status_code == 403
    assert client.get('/api/overview', headers={**headers['hasan'], 'X-ExtSecure-Device':second.json()['device_token']}).status_code == 200


def test_snapshots_store_enabled_metadata_and_preserve_removed_history(system):
    client, app, headers, _ = system
    device, browser = linked(client, headers['hasan'])
    response = client.post('/api/inventory/sync', headers=browser, json={'extensions':[SELF,OTHER]})
    assert response.status_code == 200 and response.json()['enabled_count'] == 2
    rows = client.get('/api/extensions', headers=browser).json()
    assert all(r['source']=='Chrome inventory' and r['status']=='Enabled' for r in rows)
    assert all(r['device_id']==device['id'] for r in rows)
    assert client.post('/api/inventory/sync', headers=browser, json={'extensions':[SELF]}).status_code == 200
    rows = client.get('/api/extensions', headers=browser).json()
    assert len(rows) == 2
    assert next(r for r in rows if r['extension_key']==OTHER['id'])['status']=='Not in latest snapshot'
    assert client.get('/api/devices', headers=browser).json()[0]['last_sync']
    with app.state.session_factory() as db:
        assert db.get(Device, device['id']).last_seen
        assert len(db.scalars(select(ChromeObservation)).all()) == 2


@pytest.mark.parametrize('items', [[OTHER], [SELF,SELF], [{**SELF,'id':'invalid'}], [{**SELF,'permissions':['tabs']}], []])
def test_snapshot_validation_requires_self_unique_ids_and_minimal_metadata(system, items):
    client, _, headers, _ = system
    _, browser = linked(client, headers['hasan'])
    assert client.post('/api/inventory/sync', headers=browser, json={'extensions':items}).status_code == 422


@pytest.mark.parametrize('role', ['head_administrator','administrator','manager','normal_user'])
def test_blocked_device_cannot_scan_sync_or_consume_approval_but_can_recover(roles, role):
    client, _, headers, _ = roles
    device, browser = linked(client, headers['head_administrator'])
    assert block(client, headers['head_administrator'], device).status_code == 200
    actor = {**headers[role], 'X-ExtSecure-Device':browser['X-ExtSecure-Device']}
    for path, body in [('/api/access/check', {'target':'https://example.com/'}),
                       ('/api/access/consume', {'target':'https://example.com/'}),
                       ('/api/inventory/sync', {'extensions':[SELF]}),
                       ('/api/admin/downloads/scan', {'device_id':'forged', 'device_name':'Spoof', 'sha256':'a'*64})]:
        assert client.post(path, headers=actor, json=body).status_code == 403
    assert client.get('/api/admin/me', headers=actor).json()['inventory']['blocked']
    assert client.get('/api/inventory/self', headers=actor).status_code == 200
    assert block(client, headers['head_administrator'], device, False).status_code == 200
    assert client.post('/api/access/check', headers=actor, json={'target':'https://example.com/'}).status_code == 200


def test_removing_or_forging_credential_cannot_bypass_block(system):
    client, _, headers, _ = system
    device, browser = linked(client, headers['hasan'])
    block(client, headers['hasan'], device)
    for h in [headers['hasan'], {**headers['hasan'],'X-ExtSecure-Device':device['id']},
              {**headers['hasan'],'X-ExtSecure-Device':'192.168.1.25'}]:
        assert client.post('/api/access/consume', headers=h, json={'target':'https://example.com/'}).status_code == 403


def test_stale_device_decision_fails_and_successful_decisions_are_audited(system):
    client, app, headers, _ = system
    device, browser = linked(client, headers['hasan'])
    assert block(client, headers['hasan'], device).status_code == 200
    response = client.post('/api/inventory/devices/'+device['id']+'/status', headers=headers['hasan'],
        json={'blocked':False,'expected_revision':1,'reason':'Stale administrator decision must not overwrite'})
    assert response.status_code == 409
    with app.state.session_factory() as db:
        rows = db.scalars(select(GovernanceAudit).where(GovernanceAudit.area=='inventory')).all()
        assert {r.action for r in rows} >= {'device_added','browser_paired','device_blocked'}
        assert device['pairing_code'] not in str([r.details for r in rows])


def test_trusted_ingest_cannot_record_for_blocked_device(system):
    client, _, headers, _ = system
    device, _ = linked(client, headers['hasan'])
    block(client, headers['hasan'], device)
    response = client.post('/api/scans', headers=INGEST, json={'device_id':device['id'],
        'device_name':'Spoofed device', 'target_kind':'url','target':'https://example.com/', 'signals':[]})
    assert response.status_code == 403


def test_root_extension_scan_is_blocked_before_any_external_lookup(system):
    from main import extension_scan
    client, monitor, headers, _ = system
    device, browser = linked(client, headers['hasan'])
    block(client, headers['hasan'], device)
    root = FastAPI()
    root.state.monitoring_app = monitor
    root.add_api_route('/extension/scan', extension_scan, methods=['POST'])
    with TestClient(root) as root_client:
        # No VT client is installed on this app: touching it would fail the test.
        assert root_client.post('/extension/scan', headers=browser, json={'target':'https://example.com/'}).status_code == 403


def test_url_scan_attributes_to_the_verified_device_not_username(system):
    from main import _extension_record
    client, app, headers, _ = system
    device, _ = linked(client, headers['hasan'])
    record = _extension_record(app, 'https://example.com/', 'harmless', 'hasan', device['id'])
    with app.state.session_factory() as db:
        assert db.get(Scan, record['id']).device_id == device['id']
        assert db.get(PersonalScan, record['id']).username == 'hasan'
        ext = db.scalar(select(Extension).where(Extension.device_id==device['id']))
        assert ext.extension_key == SELF['id']


def test_download_scan_ignores_forged_device_id_and_uses_linked_browser(roles, monkeypatch):
    from alba_security.file_lookup import FileVerdict
    monkeypatch.setattr('alba_security.api.lookup_file_hash', lambda *args, **kwargs: FileVerdict('clear'))
    client, app, headers, _ = roles
    device, browser = linked(client, headers['head_administrator'])
    normal = {**headers['normal_user'], 'X-ExtSecure-Device':browser['X-ExtSecure-Device']}
    response = client.post('/api/admin/downloads/scan', headers=normal,
        json={'device_id':'forged-device','device_name':'Fake workstation','sha256':'a'*64})
    assert response.status_code == 201, response.text
    with app.state.session_factory() as db:
        assert db.get(Scan, response.json()['id']).device_id == device['id']
        assert db.get(Device, device['id']).name == device['name']
        assert db.get(Device, 'forged-device') is None


@pytest.mark.parametrize('role', ['manager','normal_user'])
def test_lower_roles_cannot_unblock_or_reissue_pair_codes(roles, role):
    client, _, headers, _ = roles
    device, browser = linked(client, headers['head_administrator'])
    actor = {**headers[role], 'X-ExtSecure-Device':browser['X-ExtSecure-Device']}
    for suffix, body in [('status', {'blocked':False,'expected_revision':2,'reason':'Unauthorized unblock must fail'}),
                         ('pairing-code', {'expected_revision':2,'reason':'Unauthorized pairing reset must fail'})]:
        assert client.post('/api/inventory/devices/'+device['id']+'/'+suffix, headers=actor, json=body).status_code == 403


def test_existing_scan_inventory_is_labelled_unverified_and_keeps_history(system):
    from tests.alba.test_governance import scan
    client, _, headers, _ = system
    scan(client)
    row = client.get('/api/devices', headers=headers['hasan']).json()[0]
    assert row['registered'] is False and row['status']=='Scan record' and row['scan_count']==1


def test_relinking_current_browser_to_another_record_revokes_its_previous_identity(system):
    client, _, headers, _ = system
    first, browser = linked(client, headers['hasan'])
    second = add(client, headers['hasan'], name='Replacement workstation').json()
    assert pair(client, browser, second['pairing_code']).status_code == 200
    assert client.get('/api/overview', headers=browser).status_code == 403
    devices = client.get('/api/devices', headers=headers['hasan']).json()
    assert next(r for r in devices if r['id']==first['id'])['linked'] is False


def test_blocked_trusted_download_is_rejected_before_external_hash_lookup(system, monkeypatch):
    def unexpected_lookup(*args, **kwargs):
        raise AssertionError('Blocked device must not send hashes to VirusTotal')
    monkeypatch.setattr('alba_security.api.lookup_file_hash', unexpected_lookup)
    client, _, headers, _ = system
    device, _ = linked(client, headers['hasan'])
    block(client, headers['hasan'], device)
    assert client.post('/api/downloads/scan', headers=INGEST,
        json={'device_id':device['id'],'device_name':'Blocked device','sha256':'a'*64}).status_code == 403
