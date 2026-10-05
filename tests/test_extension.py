"""Real API contracts behind the MV3 extension; all data and lookups are isolated."""
from datetime import timedelta
from functools import partial
from io import BytesIO
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from PIL import Image
import pyotp
import zxingcpp
from sqlalchemy import select
import main
from alba_security import api as monitor_api
from alba_security.admin_auth import AdminSession, _digest
from alba_security.models import Alert, PersonalScan, Scan, Extension, utc_now
from alba_security.registration import RegisteredAdmin
from app.services.virustotal import ScanResult, RateLimitError
from tests.test_integration import _PASSWORD_HASH, _TOTP_SECRET

@pytest.fixture
def extension_client(monkeypatch):
    for key,value in {'MONITORING_ENABLED':'1','DATABASE_URL':'sqlite:///:memory:',
        'ADMIN_USERNAME':'extension-test-owner','ADMIN_PASSWORD_HASH':_PASSWORD_HASH,
        'ADMIN_TOTP_SECRET':_TOTP_SECRET,'INGEST_TOKEN':'extension-test-ingest'}.items():
        monkeypatch.setenv(key,value)
    original=monitor_api.create_app
    monkeypatch.setattr(monitor_api,'create_app',partial(original,alert_notifier=lambda **_: [{'channel':'test','status':'skipped'}]))
    application=main.create_app()
    monitor=application.state.monitoring_app
    token='synthetic-extension-owner-session'
    with monitor.state.session_factory() as db:
        db.add(AdminSession(username='extension-test-owner',token_hash=_digest(token),expires_at=utc_now()+timedelta(minutes=10)))
        db.commit()
    with TestClient(application) as client:
        client.headers['Authorization']='Bearer '+token
        yield client,monitor,application

def mock_lookup(application,verdict='harmless'):
    result=ScanResult(target='https://example.com/',scan_type='url',verdict=verdict,malicious=3 if verdict=='malicious' else 0,suspicious=0,harmless=60,undetected=5)
    application.state.vt.scan_url=AsyncMock(return_value=result)
    return application.state.vt.scan_url

def test_extension_refuses_anonymous_before_lookup(extension_client):
    client,_,application=extension_client
    lookup=mock_lookup(application)
    response=client.post('/extension/scan',headers={'Authorization':''},json={'target':'https://example.com/'})
    assert response.status_code==401
    lookup.assert_not_called()

@pytest.mark.parametrize('target',['javascript:alert(1)','https://user:password@example.com/','https://example.com/?token=private','https://example.com/#private','not a URL'])
def test_extension_rejects_private_or_invalid_targets(extension_client,target):
    client,_,application=extension_client
    lookup=mock_lookup(application)
    assert client.post('/extension/scan',json={'target':target}).status_code==422
    lookup.assert_not_called()

def test_extension_real_risk_result_and_personal_history(extension_client):
    client,monitor,application=extension_client
    mock_lookup(application)
    response=client.post('/extension/scan',json={'target':'https://example.com/'})
    assert response.status_code==201 and response.headers['cache-control']=='no-store'
    result=response.json()
    assert result['severity']=='Low' and result['score']==0 and result['lookup']['status']=='complete'
    assert client.get('/monitor/api/my/scans').json()[0]['id']==result['id']
    with monitor.state.session_factory() as db:
        assert db.scalar(select(PersonalScan)).username=='extension-test-owner'
        assert db.scalar(select(Extension)).name=='ExtSecure'

def test_unknown_upstream_creates_unknown_evidence(extension_client):
    client,_,application=extension_client
    application.state.vt.scan_url=AsyncMock(side_effect=RateLimitError())
    response=client.post('/extension/scan',json={'target':'https://example.com/'})
    assert response.status_code==200
    result=response.json()
    assert result['severity']=='Unknown' and result['score'] is None
    assert result['lookup']['status']=='unavailable'

def test_high_risk_records_alert_and_notification_outcome(extension_client):
    client,monitor,application=extension_client
    mock_lookup(application,'malicious')
    response=client.post('/extension/scan',json={'target':'https://example.com/'})
    assert response.json()['severity']=='Critical'
    with monitor.state.session_factory() as db:
        assert db.scalar(select(Alert)).status=='open'
    events=client.get('/monitor/api/events').json()
    assert any(e['event_type']=='notification_delivery' and e['channel']=='test' for e in events)

def test_cached_lookup_still_records_each_personal_scan(extension_client):
    client,monitor,application=extension_client
    lookup=mock_lookup(application)
    first=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
    second=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
    assert first['lookup']['cached'] is False and second['lookup']['cached'] is True
    assert first['id']!=second['id']
    assert lookup.await_count==1

def test_extension_rate_limit_does_not_flood_lookup(extension_client):
    client,_,application=extension_client
    lookup=mock_lookup(application)
    for _ in range(12):assert client.post('/extension/scan',json={'target':'https://example.com/'}).status_code==201
    assert client.post('/extension/scan',json={'target':'https://example.com/'}).status_code==429
    assert lookup.await_count==1

def test_extension_manager_scan_denied(extension_client):
    client,monitor,application=extension_client
    directory=monitor.state.admin_directory
    with monitor.state.session_factory() as db:
        db.add(RegisteredAdmin(username='test-manager',password_hash=_PASSWORD_HASH,totp_encrypted=directory.cipher().encrypt(_TOTP_SECRET.encode()).decode(),status='active',role='manager',approved_by=directory.primary.username))
        db.add(AdminSession(username='test-manager',token_hash=_digest('manager-session'),expires_at=utc_now()+timedelta(minutes=10)))
        db.commit()
    lookup=mock_lookup(application)
    assert client.post('/extension/scan',headers={'Authorization':'Bearer manager-session'},json={'target':'https://example.com/'}).status_code==403
    lookup.assert_not_called()

def test_machine_token_cannot_impersonate_extension_account(extension_client):
    client,_,application=extension_client
    lookup=mock_lookup(application)
    assert client.post('/extension/scan',headers={'X-Ingest-Token':'extension-test-ingest'},json={'target':'https://example.com/'}).status_code==401
    lookup.assert_not_called()

def test_extension_requires_monitoring_even_if_standalone_scan_exists(monkeypatch):
    monkeypatch.setenv('MONITORING_ENABLED','0')
    with TestClient(main.create_app()) as client:
        assert client.post('/extension/scan',json={'target':'https://example.com/'}).status_code==503

def test_registration_qr_uses_local_renderer_and_never_caches(extension_client):
    client,_,_=extension_client
    enrollment=client.post('/monitor/api/admin/register',json={'username':'qr-extension-user','password':'Synthetic registration password 2026'}).json()
    response=client.post('/monitor/api/admin/register/qr',json={'enrollment_token':enrollment['enrollment_token']})
    assert response.status_code==200 and response.headers['cache-control']=='no-store'
    assert response.headers['content-type']=='image/png'
    decoded=zxingcpp.read_barcode(Image.open(BytesIO(response.content)))
    assert pyotp.parse_uri(decoded.text).secret==enrollment['totp_secret']
    assert pyotp.parse_uri(decoded.text).issuer=='ExtSecure'

def test_registration_qr_unknown_token_rejected(extension_client):
    client,_,_=extension_client
    response=client.post('/monitor/api/admin/register/qr',json={'enrollment_token':'unknown-token-with-no-enrollment'})
    assert response.status_code==401 and response.headers['cache-control']=='no-store'
