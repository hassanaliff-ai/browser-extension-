"""Shared SecureScope evidence, privacy, risk and persistence audit."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from sqlalchemy import select

from alba_security import rdap_lookup
REAL_LOOKUP = rdap_lookup.lookup_domain_age
from alba_security.domain_age import DomainAgeService, registered_domain, age_signal
from alba_security.models import Scan, SecurityEvent, Alert
from alba_security.risk import assess, SignalInput
from tests.test_extension import extension_client, mock_lookup
from tests.test_integration import integrated_client
from tests.helpers import VT_BASE, object_payload, url_id
from httpx import Response
from app.services.virustotal import RateLimitError


@pytest.mark.parametrize('url,expected',[
 ('https://login.example.co.uk/private?token=secret','example.co.uk'),
 ('https://WWW.Example.COM:8443/a','example.com'),
 ('https://bücher.de/path','xn--bcher-kva.de'),
 ('https://tenant.github.io/','github.io'),
])
def test_registered_domain_only(url,expected):
 assert registered_domain(url)==expected


@pytest.mark.parametrize('url',['https://127.0.0.1/','http://localhost/','https://x.internal/',
 'https://user:secret@example.com/','file:///etc/passwd','https://a\\b.com/','https://example.com:broken/'])
def test_invalid_targets_never_make_rdap_request(monkeypatch,url):
 lookup=Mock();monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lookup)
 assert DomainAgeService().lookup(url)['status']=='Unknown'
 lookup.assert_not_called()


@pytest.mark.parametrize('age,status',[(0,'detected'),(29,'detected'),(30,'clear'),(1000,'clear'),(-1,'unknown'),(True,'unknown')])
def test_new_domain_boundary(age,status):
 signal=age_signal({'status':'Known','age_days':age})
 assert signal['status']==status
 result=assess([SignalInput(**signal)])
 assert result.severity not in {'High','Critical'}


def evidence(age=12):
 return {'status':'Known','domain':'example.com','age_days':age,'registered_at':'2026-10-10T00:00:00+00:00','source':'https://registry.example/domain/example.com'}


def test_cache_shares_subdomains_and_cannot_be_mutated(monkeypatch):
 lookup=Mock(return_value=evidence());monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lookup)
 service=DomainAgeService()
 first=service.lookup('https://a.example.com/private');first['age_days']=9000
 second=service.lookup('https://b.example.com/other')
 assert second['cached'] is True and second['age_days']==12
 lookup.assert_called_once_with('example.com')


def test_unknown_retry_and_bounded_cache(monkeypatch):
 clock=[0];lookup=Mock(return_value={'status':'Unknown','reason':'rate limited'})
 monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lookup)
 service=DomainAgeService(clock=lambda:clock[0],max_entries=2)
 assert not service.lookup('https://example.com')['cached']
 assert service.lookup('https://example.com')['cached']
 clock[0]=61
 assert not service.lookup('https://example.com')['cached']
 service.lookup('https://example.org');service.lookup('https://example.net')
 assert len(service.cache)==2


def test_concurrent_same_domain_has_one_lookup(monkeypatch):
 lookup=Mock(return_value=evidence());monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lookup)
 service=DomainAgeService()
 with ThreadPoolExecutor(max_workers=8) as pool:
  results=list(pool.map(service.lookup,['https://example.com']*8))
 assert sum(not r['cached'] for r in results)==1
 lookup.assert_called_once()


def test_browser_scan_persists_age_history_and_reuses_cache(extension_client,monkeypatch):
 client,monitor,application=extension_client
 lookup=Mock(return_value=evidence());monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lookup)
 mock_lookup(application)
 first=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
 second=client.post('/extension/scan',json={'target':'https://example.com/path'}).json()
 assert first['score']==15 and first['completeness']=='complete'
 assert first['domain_age']['age_days']==12 and 'domain' not in first['domain_age']
 assert 'source' not in first['domain_age']
 assert second['domain_age']['cached'] is True
 saved=client.get('/monitor/api/my/scans/'+first['id']).json()
 assert saved['domain_age']['age_days']==12
 assert next(s for s in saved['signals'] if s['code']=='new_domain')['status']=='detected'
 assert '12 days' in saved['findings'][0]['detail']
 with monitor.state.session_factory() as db:
  assert len(db.scalars(select(Scan)).all())==2
  assert db.scalar(select(Alert)) is None
 lookup.assert_called_once_with('example.com')


def test_rdap_failure_keeps_partial_and_does_not_hide_malicious(extension_client):
 client,monitor,application=extension_client;mock_lookup(application,'malicious')
 result=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
 assert result['severity']=='Critical' and result['completeness']=='partial'
 assert 'new_domain' in result['unknown_codes']
 assert result['containment']['active'] is True


def test_vt_failure_preserves_confirmed_new_domain(extension_client,monkeypatch):
 client,_,application=extension_client
 monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lambda _:evidence())
 from unittest.mock import AsyncMock
 application.state.vt.scan_url=AsyncMock(side_effect=RateLimitError())
 result=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
 assert result['score']==15 and result['completeness']=='partial'
 assert result['lookup']['status']=='unavailable'


def test_legacy_url_contract_unchanged_with_shared_evidence(integrated_client,respx_mock,monkeypatch):
 client,monitor=integrated_client
 monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lambda _:evidence())
 target='https://example.com/'
 respx_mock.get(f'{VT_BASE}/urls/{url_id(target)}').mock(return_value=Response(200,json=object_payload(harmless=20)))
 result=client.post('/scan',json={'target':target})
 assert result.status_code==200 and 'domain_age' not in result.json()
 with monitor.state.session_factory() as db:
  row=db.scalar(select(Scan));assert row.score==15
  event=db.scalar(select(SecurityEvent).where(SecurityEvent.event_type=='scan_completed'))
  assert event.details['domain_age']['age_days']==12


@pytest.mark.parametrize('events',[None,{},'bad',[None,{'eventAction':'registration','eventDate':'bad'}]])
def test_malformed_registry_events_are_unknown(events):
 result=REAL_LOOKUP('example.com',bootstrap={'services':[[['com'],['https://registry.example']]]},fetch_json=lambda _:{'objectClassName':'domain','ldhName':'example.com','events':events})
 # Call the canonical implementation, restored explicitly by the parser tests below.
 assert result['status']=='Unknown'


def test_private_registry_dns_is_rejected_before_connect(monkeypatch):
 import alba_security.content_reader as reader
 monkeypatch.setattr(reader.socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('127.0.0.1',443))])
 connection=Mock();monkeypatch.setattr(rdap_lookup,'PinnedHTTPS',connection)
 with pytest.raises(ValueError):
  rdap_lookup._fetch_json('https://registry.example/domain/example.com')
 connection.assert_not_called()


@pytest.mark.parametrize('url',['http://registry.example/','https://localhost/','https://127.0.0.1/',
 'https://registry.example:8443/','https://user:pass@registry.example/'])
def test_unsafe_registry_urls_are_rejected_without_network(monkeypatch,url):
 resolve=Mock();monkeypatch.setattr(rdap_lookup,'resolve_public',resolve)
 with pytest.raises(ValueError):rdap_lookup._fetch_json(url)
 resolve.assert_not_called()


def test_redirect_to_private_host_never_connects(monkeypatch):
 monkeypatch.setattr(rdap_lookup,'resolve_public',lambda _:['93.184.216.34'])
 connection=Mock();response=Mock(status=302)
 response.getheader.return_value='https://127.0.0.1/admin'
 connection.getresponse.return_value=response
 factory=Mock(return_value=connection);monkeypatch.setattr(rdap_lookup,'PinnedHTTPS',factory)
 with pytest.raises(ValueError):rdap_lookup._fetch_json('https://registry.example/domain/example.com')
 assert factory.call_count==1
 connection.close.assert_called_once()


def test_oversized_registry_response_fails_closed(monkeypatch):
 monkeypatch.setattr(rdap_lookup,'resolve_public',lambda _:['93.184.216.34'])
 monkeypatch.setattr(rdap_lookup,'MAX_RESPONSE_BYTES',8)
 response=Mock(status=200)
 response.getheader.return_value='identity'
 response.read1.return_value=b'123456789'
 connection=Mock();connection.getresponse.return_value=response
 monkeypatch.setattr(rdap_lookup,'PinnedHTTPS',lambda *a:connection)
 with pytest.raises(ValueError):rdap_lookup._fetch_json('https://registry.example/domain/example.com')
 connection.close.assert_called_once()


def test_unauthenticated_scan_does_not_trigger_rdap(extension_client,monkeypatch):
 client,_,_=extension_client
 lookup=Mock();monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lookup)
 assert client.post('/extension/scan',headers={'Authorization':''},json={'target':'https://example.com/'}).status_code==401
 lookup.assert_not_called()


def test_hostname_privacy_does_not_persist_registry_domain(extension_client,monkeypatch):
 from alba_security import api as monitor_api
 client,monitor,application=extension_client
 monkeypatch.setattr(rdap_lookup,'lookup_domain_age',lambda _:evidence())
 monkeypatch.setattr(monitor_api,'privacy_settings',lambda db:{'show_hostnames':False})
 mock_lookup(application)
 result=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
 assert result['target_display'].startswith('URL ')
 with monitor.state.session_factory() as db:
  event=db.scalar(select(SecurityEvent).where(SecurityEvent.event_type=='scan_completed'))
  assert 'example.com' not in str(event.details['domain_age'])
  assert 'example.com' not in str(db.scalar(select(Scan)).signals)


def test_caller_supplied_rdap_detail_is_discarded(integrated_client):
 client,monitor=integrated_client
 result=client.post('/monitor/api/scans',json={
  'device_id':'synthetic-ingest-device','device_name':'Test device','target_kind':'url','target':'https://example.com/',
  'signals':[{'code':'new_domain','status':'detected','detail':'FORGED PRIVATE EVIDENCE'}]})
 assert result.status_code==201
 assert 'FORGED' not in str(result.json())
 with monitor.state.session_factory() as db:
  assert 'FORGED' not in str(db.scalar(select(Scan)).signals)
