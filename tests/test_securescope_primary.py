"""Compatibility checks for additive SecureScope primary API staging."""
import pytest
from sqlalchemy import select
from alba_security.models import Scan,PersonalScan,Alert
from tests.test_extension import extension_client,mock_lookup
from prototypes.securescope.backend.primary import install_primary_routes


def body(url='https://example.com'):
 return {'url':url,'source':'manual','checked_at':0}


def stage(application):
 before={(getattr(r,'path',None),frozenset(getattr(r,'methods',[]))) for r in application.state.monitoring_app.routes}
 install_primary_routes(application)
 after={(getattr(r,'path',None),frozenset(getattr(r,'methods',[]))) for r in application.state.monitoring_app.routes}
 assert before==after


def test_secure_scope_is_primary_and_legacy_scan_routes_are_retired(extension_client):
 client,monitor,application=extension_client;stage(application)
 assert client.get('/health').json()=={'status':'ok','service':'SecureScope API'}
 caps=client.get('/extension/capabilities').json()
 assert caps['api_provider']=='SecureScope' and caps['scan_endpoint']=='/api/v1/check'
 assert caps['monitoring_available']
 paths=client.get('/openapi.json').json()['paths']
 assert '/api/v1/check' in paths and '/api/v1/rdap' in paths
 assert '/scan' not in paths and '/extension/scan' not in paths
 assert client.get('/monitor/api/admin/me').status_code==200


def test_native_scan_keeps_original_accounts_database_history_and_containment(extension_client):
 client,monitor,application=extension_client;stage(application);mock_lookup(application,'malicious')
 response=client.post('/api/v1/check',json=body())
 assert response.status_code==201
 result=response.json()
 assert result['api_provider']=='SecureScope' and result['origin']=='https://example.com'
 assert result['severity']=='Critical' and result['containment']['active']
 assert result['reasons'] and result['lookup_status']=='partial'
 assert client.get('/monitor/api/my/scans/'+result['id']).status_code==200
 with monitor.state.session_factory() as db:
  assert db.scalar(select(Scan)).id==result['id']
  assert db.scalar(select(PersonalScan)).username=='extension-test-owner'
  assert db.scalar(select(Alert)).status=='open'


@pytest.mark.parametrize('path,payload',[
 ('/api/v1/check',body()),('/api/v1/rdap',{'origin':'https://example.com'})])
def test_native_routes_do_not_bypass_account_authentication(extension_client,path,payload):
 client,_,application=extension_client;stage(application);lookup=mock_lookup(application)
 assert client.post(path,headers={'Authorization':''},json=payload).status_code==401
 lookup.assert_not_called()


@pytest.mark.parametrize('url',[
 'https://user:secret@example.com/','https://example.com/?token=secret',
 'https://example.com/#private','https://example.com/\nprivate'])
def test_native_contract_rejects_private_url_components(extension_client,url):
 client,_,application=extension_client;stage(application);lookup=mock_lookup(application)
 assert client.post('/api/v1/check',json=body(url)).status_code==422
 lookup.assert_not_called()


def test_rdap_native_route_reuses_server_lookup_without_exposing_registry_url(extension_client,monkeypatch):
 client,_,application=extension_client;stage(application)
 monkeypatch.setattr(application.state.domain_age,'lookup',lambda _: {'status':'Known','age_days':90,'source':'https://registry.example/domain/example.com'})
 result=client.post('/api/v1/rdap',json={'origin':'https://example.com'})
 assert result.status_code==200 and result.json()['age_days']==90
 assert 'source' not in result.json()


def test_monitoring_data_stays_protected_in_primary_application(extension_client):
 client,_,application=extension_client;stage(application)
 for path in ['overview','scans','devices','cases','alerts','events']:
  assert client.get('/monitor/api/'+path,headers={'Authorization':''}).status_code==401
 assert client.get('/monitor/api/overview').status_code==200
 assert client.get('/monitor/api/reports/monthly?year=2026&month=9').status_code==200


def test_lan_package_points_csp_and_worker_to_the_same_primary_gateway(tmp_path):
 import json,zipfile
 from pathlib import Path
 from scripts.package_lan_extension import build
 root=Path(__file__).resolve().parents[1]
 certificate=tmp_path/'public.cer';certificate.write_bytes(b'test-only-public-certificate')
 archive=tmp_path/'extension.zip'
 origin=build(root,'192.168.1.50',8766,certificate,archive)
 with zipfile.ZipFile(archive) as release:
  assert origin in release.read('core.js').decode()
  policy=json.loads(release.read('manifest.json'))['content_security_policy']['extension_pages']
  assert 'connect-src '+origin+';' in policy
  assert 'localhost:8001' not in policy
  assert '/api/v1/check' in release.read('background.js').decode()
  assert release.testzip() is None
