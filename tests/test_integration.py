"""The legacy scan API feeds the administrator risk and history views."""

import hashlib
from unittest.mock import Mock

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import select

import main
from alba_security import api as monitoring_api
from alba_security.models import Alert, Finding, Scan, SecurityEvent
from tests.helpers import VT_BASE, object_payload, url_id


_PASSWORD_HASH = PasswordHasher().hash("synthetic-test-password")
_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_SHA256 = "a" * 64
_MD5 = "b" * 32


@pytest.fixture
def integrated_client(monkeypatch):
    monkeypatch.setenv("MONITORING_ENABLED", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("ADMIN_USERNAME", "test-admin")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", _PASSWORD_HASH)
    monkeypatch.setenv("ADMIN_TOTP_SECRET", _TOTP_SECRET)
    monkeypatch.delenv("INGEST_TOKEN", raising=False)
    application = main.create_app()
    with TestClient(application) as client:
        yield client, application.state.monitoring_app


def _records(monitor, model):
    with monitor.state.session_factory() as db:
        return list(db.scalars(select(model).order_by(model.id)))


def test_monitor_is_optional_when_admin_configuration_is_incomplete(monkeypatch):
    for key in ("DATABASE_URL", "ADMIN_USERNAME", "ADMIN_PASSWORD_HASH", "ADMIN_TOTP_SECRET"):
        monkeypatch.delenv(key, raising=False)
    application = main.create_app()
    assert application.state.monitoring_app is None
    assert all(route.path != "/monitor" for route in application.routes)


def test_mounted_monitor_requires_admin_and_ingest_auth(integrated_client):
    client, monitor = integrated_client
    assert monitor is not None
    assert client.get("/monitor/health").json() == {"status": "ok"}
    assert client.get("/monitor/api/overview").status_code == 401
    unauthenticated = client.post("/monitor/api/scans", json={})
    assert unauthenticated.status_code == 401
    assert client.post("/monitor/api/scans", headers={"X-Ingest-Token": "guessed"}, json={}).status_code == 401
    assert "synthetic-test-password" not in client.get("/monitor/openapi.json").text


@pytest.mark.parametrize(
    ("target", "scan_type", "stats", "expected_kind", "expected_severity", "detected_code"),
    [
        ("https://example.com/private?secret=1", "url", {"malicious": 4}, "url", "Critical", "malicious_url"),
        (_SHA256, "hash", {"malicious": 4}, "download", "Critical", "malicious_file_hash"),
        (_MD5, "hash", {"malicious": 1}, "hash", "Medium", "suspicious_file_hash"),
        ("8.8.8.8", "ip", {"suspicious": 3}, "ip", "Medium", "suspicious_ip"),
    ],
)
def test_public_scan_is_recorded_without_sending_notifications(
    integrated_client, respx_mock, monkeypatch, target, scan_type, stats, expected_kind, expected_severity, detected_code
):
    client, monitor = integrated_client
    notifier = Mock()
    monkeypatch.setattr(monitoring_api, "send_high_severity_alert", notifier)
    if scan_type == "url":
        vt_path = f"{VT_BASE}/urls/{url_id(target)}"
    elif scan_type == "ip":
        vt_path = f"{VT_BASE}/ip_addresses/{target}"
    else:
        vt_path = f"{VT_BASE}/files/{target}"
    respx_mock.get(vt_path).mock(return_value=Response(200, json=object_payload(**stats)))

    response = client.post("/scan", json={"target": target, "scan_type": scan_type})

    assert response.status_code == 200
    assert set(response.json()) == {
        "target", "scan_type", "verdict", "malicious", "suspicious", "harmless", "undetected", "cached"
    }
    scans = _records(monitor, Scan)
    assert len(scans) == 1
    assert scans[0].target_kind == expected_kind
    assert scans[0].severity == expected_severity
    assert scans[0].device_id == "public-unidentified"
    assert [finding.signal_code for finding in _records(monitor, Finding)] == [detected_code]
    assert "scan_completed" in [event.event_type for event in _records(monitor, SecurityEvent)]
    assert "notification_delivery" not in [event.event_type for event in _records(monitor, SecurityEvent)]
    notifier.assert_not_called()
    if expected_severity == "Critical":
        assert len(_records(monitor, Alert)) == 1
    else:
        assert _records(monitor, Alert) == []
    if scan_type == "url":
        assert scans[0].target_fingerprint == hashlib.sha256(target.encode()).hexdigest()
        assert scans[0].target_display == "example.com"


def test_cached_scan_still_creates_a_history_record(integrated_client, respx_mock):
    client, monitor = integrated_client
    target = "1.2.3.4"
    route = respx_mock.get(f"{VT_BASE}/ip_addresses/{target}").mock(
        return_value=Response(200, json=object_payload(harmless=10))
    )
    first = client.post("/scan", json={"target": target, "scan_type": "ip"})
    second = client.post("/scan", json={"target": target, "scan_type": "ip"})
    assert first.status_code == second.status_code == 200
    assert first.json()["cached"] is False
    assert second.json()["cached"] is True
    assert route.call_count == 1
    assert len(_records(monitor, Scan)) == 2


@pytest.mark.parametrize(
    ("target", "scan_type", "vt_status", "expected_status"),
    [(_SHA256, "hash", 404, 404), ("8.8.8.8", "ip", 429, 429), ("1.1.1.1", "ip", 401, 502)],
)
def test_upstream_failures_keep_legacy_error_and_record_unknown(
    integrated_client, respx_mock, target, scan_type, vt_status, expected_status
):
    client, monitor = integrated_client
    vt_kind = "files" if scan_type == "hash" else "ip_addresses"
    respx_mock.get(f"{VT_BASE}/{vt_kind}/{target}").mock(return_value=Response(vt_status))
    response = client.post("/scan", json={"target": target, "scan_type": scan_type})
    assert response.status_code == expected_status
    assert len(_records(monitor, Scan)) == 1
    recorded = _records(monitor, Scan)[0]
    assert recorded.severity == "Unknown"
    assert recorded.completeness == "unknown"
    assert _records(monitor, Finding) == []


def test_invalid_target_does_not_create_history(integrated_client, respx_mock):
    client, monitor = integrated_client
    response = client.post("/scan", json={"target": "not-an-ip", "scan_type": "ip"})
    assert response.status_code == 422
    assert _records(monitor, Scan) == []
    assert respx_mock.calls.call_count == 0


def test_record_failure_returns_503_instead_of_unrecorded_success(integrated_client, respx_mock, monkeypatch):
    client, monitor = integrated_client
    target = "8.8.8.8"
    respx_mock.get(f"{VT_BASE}/ip_addresses/{target}").mock(
        return_value=Response(200, json=object_payload(harmless=10))
    )

    def cannot_record(*_args, **_kwargs):
        raise RuntimeError("synthetic write failure")

    monkeypatch.setattr(monitor.state, "record_scan", cannot_record)
    response = client.post("/scan", json={"target": target, "scan_type": "ip"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Scan result could not be recorded."}


def test_unknown_record_failure_does_not_hide_upstream_error(integrated_client, respx_mock, monkeypatch):
    client, monitor = integrated_client
    target = "8.8.8.8"
    respx_mock.get(f"{VT_BASE}/ip_addresses/{target}").mock(return_value=Response(429))

    def cannot_record(*_args, **_kwargs):
        raise RuntimeError("synthetic write failure")

    monkeypatch.setattr(monitor.state, "record_scan", cannot_record)
    response = client.post("/scan", json={"target": target, "scan_type": "ip"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
