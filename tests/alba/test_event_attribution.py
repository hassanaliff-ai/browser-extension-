"""Device/user attribution uses verified browser identity, including older scans."""
from sqlalchemy import select
from alba_security.file_lookup import FileVerdict
from alba_security.models import Device, PersonalScan, SecurityEvent
from alba_security.governance import GovernanceState
from tests.alba.test_inventory import linked
from tests.alba.test_governance import system, INGEST  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401


def test_download_events_use_verified_user_and_device_not_payload(roles, monkeypatch):
    client, app, headers, _ = roles
    monkeypatch.setattr('alba_security.api.lookup_file_hash', lambda *a, **k: FileVerdict('malicious', malicious_count=5))
    device, browser = linked(client, headers['head_administrator'])
    user = {**headers['normal_user'], 'X-ExtSecure-Device': browser['X-ExtSecure-Device']}
    result = client.post('/api/admin/downloads/scan', headers=user,
        json={'device_id': 'spoof-device', 'device_name': 'Spoof name', 'sha256': 'a'*64})
    assert result.status_code == 201, result.text
    events = client.get('/api/events', headers=browser).json()
    threat = next(r for r in events if r['event_type'] == 'threat_detected')
    assert threat['device_id'] == device['id']
    assert threat['device_name'] == device['name']
    assert threat['username'] == threat['actor'] == 'normal_user'
    assert threat['target_kind'] == 'download' and threat['target_display'].startswith('SHA-256 '+ 'a'*12)
    assert client.get('/api/events', headers=user).status_code == 403
    with app.state.session_factory() as db:
        db.get(Device, device['id']).name = 'Renamed later'
        db.commit()
    assert next(r for r in client.get('/api/events', headers=browser).json()
        if r['id'] == threat['id'])['device_name'] == device['name']


def test_url_events_include_scanner_and_preserve_url_privacy(roles):
    from main import _extension_record
    client, app, headers, _ = roles
    device, browser = linked(client, headers['head_administrator'])
    result = _extension_record(app, 'https://example.com/private?token=SECRET', 'malicious', 'normal_user', device['id'])
    events = client.get('/api/events', headers=browser).json()
    row = next(r for r in events if r['event_type']=='threat_detected' and r['scan_id']==result['id'])
    assert row['username']=='normal_user' and row['device_id']==device['id']
    assert row['target_kind']=='url' and 'SECRET' not in str(events)
    with app.state.session_factory() as db:
        privacy=db.get(GovernanceState, 'privacy')
        privacy.data={**privacy.data,'show_hostnames':False}
        db.commit()
    private=next(r for r in client.get('/api/events',headers=browser).json() if r['id']==row['id'])
    assert private['target_display'].startswith('URL ') and 'example.com' not in private['target_display']


def test_older_events_resolve_personal_owner_and_machine_scans_do_not_invent_users(system):
    from tests.alba.test_governance import scan
    client, app, headers, _ = system
    result=scan(client)
    rows=client.get('/api/events',headers=headers['hasan']).json()
    assert all(r['username'] is None for r in rows)
    assert rows[0]['device_name']=='Test device'
    with app.state.session_factory() as db:
        db.add(PersonalScan(scan_id=result['id'],username='historical-user'))
        db.commit()
    rows=client.get('/api/events',headers=headers['hasan']).json()
    assert all(r['username']=='historical-user' for r in rows)
