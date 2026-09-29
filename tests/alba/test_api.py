"""Integration tests for scan ingestion and administrator monitoring."""

import json
import sqlite3

import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from alba_security.admin_auth import AdminAuth
from alba_security.api import create_app


ADMIN_USERNAME = "test-administrator"
ADMIN_PASSWORD = "test-admin-password"
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
INGEST_HEADERS = {"X-Ingest-Token": "ingest-test-secret"}


def sign_in(client):
    first = client.post(
        "/api/admin/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert first.status_code == 200, first.text
    second = client.post(
        "/api/admin/verify",
        json={"challenge_token": first.json()["challenge_token"], "totp_code": pyotp.TOTP(TOTP_SECRET).now()},
    )
    assert second.status_code == 200, second.text
    return {"Authorization": f"Bearer {second.json()['access_token']}"}


@pytest.fixture
def api(tmp_path):
    database_file = tmp_path / "security-events.sqlite3"
    app = create_app(
        database_url=f"sqlite:///{database_file.as_posix()}",
        admin_auth=AdminAuth(
            username=ADMIN_USERNAME,
            password_hash=PasswordHasher().hash(ADMIN_PASSWORD),
            totp_secret=TOTP_SECRET,
        ),
        ingest_token="ingest-test-secret",
        alert_notifier=lambda **_kwargs: [],
    )
    with TestClient(app) as client:
        client.admin_headers = sign_in(client)
        yield client, database_file


def submit_scan(client, *, target_kind="url", target="https://example.org/", signals=None, **extra):
    body = {
        "device_id": "device-1",
        "device_name": "Lab laptop",
        "extension_key": "sample-extension",
        "extension_name": "Sample extension",
        "extension_version": "1.2.0",
        "target_kind": target_kind,
        "target": target,
        "signals": signals if signals is not None else [],
    }
    body.update(extra)
    return client.post("/api/scans", json=body, headers=INGEST_HEADERS)


def admin_get(client, endpoint):
    response = client.get(f"/api/{endpoint}", headers=client.admin_headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_critical_url_scan_creates_monitoring_records_without_storing_url(api):
    client, database_file = api
    private_url = "https://example.org/private-case-123?token=private-456"

    response = submit_scan(
        client,
        target=private_url,
        signals=[
            {
                "code": "malicious_url",
                "status": "detected",
                "detail": f"Detection at {private_url}",
            }
        ],
    )
    assert response.status_code in (200, 201), response.text
    result = response.json()
    assert result["score"] == 80
    assert result["severity"] == "Critical"
    assert result["completeness"] == "complete"
    assert result["findings"][0]["code"] == "malicious_url"

    overview = admin_get(client, "overview")
    assert overview["total_scans"] == 1
    assert overview["high_risk"] == 1
    assert overview["open_alerts"] == 1
    assert overview["devices"] == 1
    assert overview["extensions"] == 1
    assert overview["severity_counts"]["Critical"] == 1

    devices = admin_get(client, "devices")
    extensions = admin_get(client, "extensions")
    scans = admin_get(client, "scans")
    findings = admin_get(client, "findings")
    alerts = admin_get(client, "alerts")
    events = admin_get(client, "events")

    assert len(devices) == 1
    assert devices[0]["scan_count"] == 1
    assert devices[0]["highest_severity"] == "Critical"
    assert len(extensions) == 1
    assert extensions[0]["scan_count"] == 1
    assert extensions[0]["highest_severity"] == "Critical"
    assert len(findings) == 1
    assert scans[0]["target_display"] == "example.org"
    assert scans[0]["score"] == 80
    assert scans[0]["completeness"] == "complete"
    assert findings[0]["signal_code"] == "malicious_url"
    assert findings[0]["scan_id"] == result["id"]
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "Critical"
    assert alerts[0]["status"] == "open"
    assert {event["event_type"] for event in events} == {
        "scan_completed",
        "threat_detected",
    }
    assert all(event["score"] == 80 for event in events)
    assert all(event["completeness"] == "complete" for event in events)

    # A target can include private paths and query strings. Neither the display
    # API nor persistent records should retain them when only the URL is sent.
    public_data = json.dumps(
        [result, overview, devices, extensions, scans, findings, alerts, events]
    )
    with sqlite3.connect(database_file) as database:
        database_dump = "\n".join(database.iterdump())
    for private_fragment in ("private-case-123", "private-456", private_url):
        assert private_fragment not in public_data
        assert private_fragment not in database_dump


def test_unknown_lookup_remains_unknown_and_does_not_raise_alert(api):
    client, _ = api
    response = submit_scan(
        client,
        signals=[{"code": "malicious_url", "status": "unknown"}],
    )
    assert response.status_code in (200, 201), response.text
    result = response.json()
    assert result["score"] is None
    assert result["severity"] == "Unknown"
    assert result["completeness"] == "unknown"
    assert result["unknown_codes"] == ["malicious_url"]
    assert admin_get(client, "findings") == []
    assert admin_get(client, "alerts") == []
    assert admin_get(client, "overview")["severity_counts"]["Unknown"] == 1
    events = admin_get(client, "events")
    assert len(events) == 1
    assert events[0]["event_type"] == "scan_completed"
    assert events[0]["severity"] == "Unknown"


def test_downloaded_file_hash_uses_risk_logic_and_appears_in_dashboard(api):
    client, _ = api
    file_hash = "a" * 64
    response = submit_scan(
        client,
        target_kind="download",
        target=file_hash,
        signals=[{"code": "malicious_file_hash", "status": "detected"}],
    )
    assert response.status_code in (200, 201), response.text
    result = response.json()
    assert result["score"] == 90
    assert result["severity"] == "Critical"
    assert result["findings"][0]["code"] == "malicious_file_hash"
    assert admin_get(client, "overview")["high_risk"] == 1
    assert admin_get(client, "findings")[0]["signal_code"] == "malicious_file_hash"
    assert len(admin_get(client, "alerts")) == 1


def test_admin_2fa_session_and_ingest_token_guard_sensitive_endpoints(api):
    client, _ = api
    response = submit_scan(client, signals=[{"code": "new_domain", "status": "clear"}])
    assert response.status_code in (200, 201), response.text

    for endpoint in ("overview", "devices", "extensions", "scans", "findings", "alerts", "events"):
        for headers in (
            {},
            {"X-Admin-Token": "admin-test-secret"},
            {"Authorization": "Bearer incorrect"},
            INGEST_HEADERS,
        ):
            denied = client.get(f"/api/{endpoint}", headers=headers)
            assert denied.status_code in (401, 403), (endpoint, denied.text)

    scan_body = {
        "device_id": "device-2",
        "device_name": "Another laptop",
        "target_kind": "url",
        "target": "https://example.org/",
        "signals": [{"code": "malicious_url", "status": "detected"}],
    }
    for headers in ({}, {"X-Ingest-Token": "incorrect"}, client.admin_headers):
        denied = client.post("/api/scans", json=scan_body, headers=headers)
        assert denied.status_code in (401, 403), denied.text

    assert admin_get(client, "overview")["total_scans"] == 1


def test_scan_counts_roll_up_across_devices_and_extensions(api):
    client, _ = api
    cases = [
        {
            "device_id": "device-1",
            "device_name": "Lab laptop",
            "extension_key": "sample-extension",
            "extension_name": "Sample extension",
            "signals": [{"code": "malicious_url", "status": "detected"}],
        },
        {
            "device_id": "device-1",
            "device_name": "Lab laptop",
            "extension_key": "sample-extension",
            "extension_name": "Sample extension",
            "signals": [{"code": "new_domain", "status": "clear"}],
        },
        {
            "device_id": "device-2",
            "device_name": "Home laptop",
            "extension_key": None,
            "extension_name": None,
            "signals": [{"code": "suspicious_url", "status": "detected"}],
        },
    ]
    for case in cases:
        response = submit_scan(client, **case)
        assert response.status_code in (200, 201), response.text

    overview = admin_get(client, "overview")
    assert overview["total_scans"] == 3
    assert overview["devices"] == 2
    assert overview["extensions"] == 1
    assert overview["high_risk"] == 1
    assert overview["severity_counts"]["Critical"] == 1
    assert overview["severity_counts"]["Medium"] == 1
    assert overview["severity_counts"]["Low"] == 1
    assert {device["id"]: device["scan_count"] for device in admin_get(client, "devices")} == {
        "device-1": 2,
        "device-2": 1,
    }
    assert admin_get(client, "extensions")[0]["scan_count"] == 2
