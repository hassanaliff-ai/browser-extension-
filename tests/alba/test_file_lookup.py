"""Downloaded-file reputation checks use the provider safely and visibly."""

import hashlib

import httpx
import pyotp
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from alba_security.admin_auth import AdminAuth
from alba_security.api import create_app


INGEST = {"X-Ingest-Token": "ingest-test-secret"}
ADMIN_USERNAME = "test-administrator"
ADMIN_PASSWORD = "test-admin-password"
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _admin_headers(api):
    first = api.post(
        "/api/admin/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert first.status_code == 200, first.text
    second = api.post(
        "/api/admin/verify",
        json={"challenge_token": first.json()["challenge_token"], "totp_code": pyotp.TOTP(TOTP_SECRET).now()},
    )
    assert second.status_code == 200, second.text
    return {"Authorization": f"Bearer {second.json()['access_token']}"}


def _app(tmp_path, transport, key="test-vt-key"):
    client = httpx.Client(transport=httpx.MockTransport(transport))
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'file-lookup.db').as_posix()}",
        admin_auth=AdminAuth(
            username=ADMIN_USERNAME,
            password_hash=PasswordHasher().hash(ADMIN_PASSWORD),
            totp_secret=TOTP_SECRET,
        ),
        ingest_token="ingest-test-secret",
        vt_api_key=key,
        vt_client=client,
        alert_notifier=lambda **_kwargs: [],
    )
    return TestClient(app), client


def _body(digest):
    return {"device_id": "device-1", "device_name": "Lab laptop", "sha256": digest}


def test_malicious_download_uses_server_lookup_and_cache(tmp_path):
    digest = "a" * 64
    requests = []

    def provider(request):
        requests.append(request)
        return httpx.Response(200, json={"data": {"id": digest, "type": "file", "attributes": {
            "last_analysis_stats": {"malicious": 4, "suspicious": 0, "harmless": 30}
        }}})

    api, provider_client = _app(tmp_path, provider)
    with api, provider_client:
        first = api.post("/api/downloads/scan", json=_body(digest), headers=INGEST)
        assert first.status_code == 201, first.text
        assert first.json()["score"] == 90
        assert first.json()["severity"] == "Critical"
        assert first.json()["file_lookup"]["verdict"] == "malicious"
        assert not first.json()["file_lookup"]["cache_hit"]
        assert requests[0].url == f"https://www.virustotal.com/api/v3/files/{digest}"
        assert requests[0].headers["x-apikey"] == "test-vt-key"
        second = api.post("/api/downloads/scan", json=_body(digest), headers=INGEST)
        assert second.json()["file_lookup"]["cache_hit"]
        assert len(requests) == 1
        admin_headers = _admin_headers(api)
        scans = api.get("/api/scans", headers=admin_headers).json()
        assert len(scans) == 2
        assert all(row["target_kind"] == "download" for row in scans)
        assert all(row["finding_codes"] == ["malicious_file_hash"] for row in scans)
        assert len(api.get("/api/alerts", headers=admin_headers).json()) == 2


def test_suspicious_download_becomes_medium_risk(tmp_path):
    def provider(_request):
        return httpx.Response(200, json={"data": {"id": "b" * 64, "type": "file", "attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 2, "undetected": 10}
        }}})

    api, provider_client = _app(tmp_path, provider)
    with api, provider_client:
        response = api.post("/api/downloads/scan", json=_body("b" * 64), headers=INGEST)
        assert response.status_code == 201, response.text
        assert response.json()["score"] == 40
        assert response.json()["severity"] == "Medium"
        assert [item["code"] for item in response.json()["findings"]] == ["suspicious_file_hash"]


def test_unknown_provider_result_is_not_treated_as_clean(tmp_path):
    def provider(_request):
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    api, provider_client = _app(tmp_path, provider)
    with api, provider_client:
        response = api.post("/api/downloads/scan", json=_body("c" * 64), headers=INGEST)
        assert response.status_code == 201, response.text
        assert response.json()["score"] is None
        assert response.json()["severity"] == "Unknown"
        assert response.json()["file_lookup"]["reason"] == "not_found"
        assert api.get("/api/alerts", headers=_admin_headers(api)).json() == []


def test_provider_rate_limit_returns_unknown_without_losing_scan(tmp_path):
    def provider(_request):
        return httpx.Response(429, headers={"Retry-After": "120"})

    api, provider_client = _app(tmp_path, provider)
    with api, provider_client:
        response = api.post("/api/downloads/scan", json=_body("d" * 64), headers=INGEST)
        assert response.status_code == 201, response.text
        assert response.json()["severity"] == "Unknown"
        assert response.json()["file_lookup"]["reason"] == "rate_limited"
        assert response.json()["file_lookup"]["retry_after_seconds"] == 120


def test_uploaded_download_is_hashed_and_not_stored(tmp_path):
    file_bytes = b"test download bytes"
    digest = hashlib.sha256(file_bytes).hexdigest()

    def provider(request):
        assert request.url.path.endswith(digest)
        return httpx.Response(200, json={"data": {"id": digest, "type": "file", "attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 3}
        }}})

    api, provider_client = _app(tmp_path, provider)
    with api, provider_client:
        response = api.post(
            "/api/downloads/scan-file",
            headers=INGEST,
            data={"device_id": "device-1", "device_name": "Lab laptop"},
            files={"file": ("private-document.txt", file_bytes)},
        )
        assert response.status_code == 201, response.text
        assert response.json()["severity"] == "Low"
        assert response.json()["target_display"].startswith(f"SHA-256 {digest[:12]}")
        assert "private-document.txt" not in response.text
        assert file_bytes.decode() not in response.text
