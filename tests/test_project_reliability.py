"""Regression cases for reliability findings from the project-wide audit."""
import asyncio
import json
import threading
import zipfile
from unittest.mock import AsyncMock

import pytest

from alba_security.domain_age import DomainAgeService
from tests.test_extension import extension_client,mock_lookup
from scripts import start_public_api as release


@pytest.mark.parametrize('target',[
 'https://@example.com/','https://:secret@example.com/',
 'https://example.com/\nsecret','https://example.com\\private',
])
def test_browser_rejects_ambiguous_urls_before_lookup(extension_client,target):
 client,_,application=extension_client
 lookup=mock_lookup(application)
 assert client.post('/extension/scan',json={'target':target}).status_code==422
 lookup.assert_not_awaited()


@pytest.mark.anyio
async def test_rdap_timeout_does_not_release_capacity_until_thread_finishes(monkeypatch):
 service=DomainAgeService();gate=threading.Event()
 monkeypatch.setattr(service,'lookup',lambda _: (gate.wait(2) or {'status':'Unknown'}))
 try:
  result=await service.async_lookup('https://example.com',timeout=.01)
  assert result['status']=='Unknown'
  # The timed-out work is still bounded: seven free slots, one running.
  for _ in range(7):assert service.capacity.acquire(blocking=False)
  assert not service.capacity.acquire(blocking=False)
  for _ in range(7):service.capacity.release()
 finally:
  gate.set();service.close()


@pytest.mark.anyio
async def test_rdap_overload_and_closed_service_return_unknown():
 service=DomainAgeService()
 for _ in range(8):service.capacity.acquire()
 try:assert (await service.async_lookup('https://example.com'))['status']=='Unknown'
 finally:
  for _ in range(8):service.capacity.release()
 service.close()
 assert (await service.async_lookup('https://example.com'))['status']=='Unknown'


def test_browser_starts_reputation_while_rdap_is_running(extension_client,monkeypatch):
 client,_,application=extension_client
 started=threading.Event();release_age=threading.Event()
 def age(_):
  started.set();release_age.wait(2)
  return {'status':'Known','age_days':45}
 monkeypatch.setattr(application.state.domain_age,'lookup',age)
 result=mock_lookup(application).return_value
 async def reputation(_):
  for _ in range(200):
   if started.is_set():break
   await asyncio.sleep(.001)
  assert started.is_set()
  release_age.set()
  return result
 application.state.vt.scan_url=AsyncMock(side_effect=reputation)
 try:
  response=client.post('/extension/scan',json={'target':'https://example.com/'})
  assert response.status_code==201 and response.json()['completeness']=='complete'
 finally:release_age.set()


def test_reputation_deadline_is_recorded_without_inventing_safe_result(extension_client):
 client,_,application=extension_client
 application.state.vt.scan_url=AsyncMock(side_effect=asyncio.TimeoutError())
 result=client.post('/extension/scan',json={'target':'https://example.com/'}).json()
 assert result['severity']=='Unknown' and result['score'] is None
 assert result['lookup']['status']=='unavailable'


@pytest.fixture
def package_root(tmp_path,monkeypatch):
 monkeypatch.setattr(release,'ROOT',tmp_path)
 extension=tmp_path/'extension';extension.mkdir()
 (extension/'core.js').write_text("export const API_ORIGIN = 'http://127.0.0.1:8001';\nexport const VERSION = 'test';")
 (extension/'manifest.json').write_text(json.dumps({'version':'test','content_security_policy':{'extension_pages':"script-src 'self'; connect-src http://127.0.0.1:8001;"}}))
 return tmp_path


def test_completed_zip_replaces_previous_release_atomically(package_root):
 target=package_root/'ExtSecure Chrome Extension.zip';target.write_bytes(b'old release')
 archive=release.package('https://api.example')
 with zipfile.ZipFile(archive) as z:
  assert z.testzip() is None
  assert b'https://api.example' in z.read('core.js')
 assert not list(package_root.glob('.extsecure-package-*.tmp'))


def test_failed_build_preserves_previous_release(package_root,monkeypatch):
 target=package_root/'ExtSecure Chrome Extension.zip';target.write_bytes(b'working release')
 from pathlib import Path
 original=Path.read_bytes
 def read(file):
  if file.name=='manifest.json':raise OSError('simulated read failure')
  return original(file)
 monkeypatch.setattr(Path,'read_bytes',read)
 with pytest.raises(OSError):release.package('https://api.example')
 assert target.read_bytes()==b'working release'
 assert not list(package_root.glob('.extsecure-package-*.tmp'))


@pytest.mark.parametrize('origin',[
 'http://remote.example','https://api.example/path','https://user:pass@api.example',
 "https://api.example;script-src'unsafe-eval'",'https://api.example/?token=secret',
])
def test_package_rejects_unsafe_api_origins(package_root,origin):
 with pytest.raises(ValueError):release.package(origin)
 assert not (package_root/'ExtSecure Chrome Extension.zip').exists()


def test_mismatched_worker_version_does_not_replace_working_zip(package_root):
 target=package_root/'ExtSecure Chrome Extension.zip';target.write_bytes(b'working release')
 (package_root/'extension/core.js').write_text("export const API_ORIGIN = 'http://127.0.0.1:8001'; export const VERSION = 'different';")
 with pytest.raises(ValueError,match='versions do not match'):release.package('https://api.example')
 assert target.read_bytes()==b'working release'
