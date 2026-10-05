"""Administrator workflows keep authorization, evidence and audit history connected."""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from alba_security.admin_auth import AdminAuth
from alba_security.api import create_app
from alba_security.models import Scan


SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
INGEST = {"X-Ingest-Token": "trusted-test-ingest"}


@pytest.fixture
def console(tmp_path):
    provider_requests, notifications = [], []

    def provider(request):
        provider_requests.append(request)
        return httpx.Response(200, json={"data": {"id": request.url.path.rsplit("/", 1)[-1], "type": "file", "attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 40}
        }}})

    def notify(**payload):
        notifications.append(payload)
        return []

    database = tmp_path / "console.db"
    with httpx.Client(transport=httpx.MockTransport(provider)) as upstream:
        app = create_app(
            database_url=f"sqlite:///{database.as_posix()}", ingest_token=INGEST["X-Ingest-Token"],
            vt_api_key="mock-provider-key", vt_client=upstream, alert_notifier=notify,
            admin_auth=AdminAuth(username="analyst", password_hash=PasswordHasher().hash("test-passphrase"),
                                 totp_secret=SECRET),
        )
        with TestClient(app) as client:
            challenge = client.post("/api/admin/login", json={"username": "analyst", "password": "test-passphrase"}).json()["challenge_token"]
            session = client.post("/api/admin/verify", json={"challenge_token": challenge, "totp_code": pyotp.TOTP(SECRET).now()})
            assert session.status_code == 200
            headers = {"Authorization": f"Bearer {session.json()['access_token']}"}
            yield client, headers, provider_requests, notifications, database


def create_threat(client):
    response = client.post("/api/scans", headers=INGEST, json={
        "device_id": "workstation-1", "device_name": "Test workstation", "target_kind": "url",
        "target": "https://example.invalid/private-record?token=private-token",
        "signals": [{"code": "malicious_url", "status": "detected"},
                    {"code": "new_domain", "status": "unknown"}],
    })
    assert response.status_code == 201
    return response.json()


def test_new_workflows_require_completed_2fa(console):
    client, headers, requests, _, _ = console
    challenge = client.post("/api/admin/login", json={"username": "analyst", "password": "test-passphrase"}).json()["challenge_token"]
    for unauthorized in ({}, INGEST, {"Authorization": f"Bearer {challenge}"}):
        for route in ("/api/risk-policy", "/api/scans/does-not-exist"):
            assert client.get(route, headers=unauthorized).status_code == 401
        assert client.post("/api/admin/downloads/scan", headers=unauthorized,
                           json={"device_id": "test", "device_name": "Test", "sha256": "a" * 64}).status_code == 401
        assert client.post("/api/admin/downloads/scan-file", headers=unauthorized,
                           data={"device_id": "test", "device_name": "Test"},
                           files={"file": ("test.bin", b"test")}).status_code == 401
        assert client.post("/api/alerts/missing/status", headers=unauthorized,
                           json={"status": "resolved", "reason": "Reviewed evidence"}).status_code == 401
    assert requests == []
    assert client.get("/api/risk-policy", headers=headers).status_code == 200


def test_admin_download_hash_uses_provider_and_keeps_ingest_boundary(console):
    client, headers, requests, notifications, _ = console
    payload = {"device_id": "admin-review", "device_name": "Analyst review", "sha256": "c" * 64}
    assert client.post("/api/downloads/scan", headers=headers, json=payload).status_code == 401
    result = client.post("/api/admin/downloads/scan", headers=headers, json=payload)
    assert result.status_code == 201
    assert result.json()["severity"] == "Critical"
    assert result.json()["suggested_action"]
    assert len(requests) == 1 and requests[0].url.path.endswith("c" * 64)
    assert requests[0].content == b""
    assert len(notifications) == 1


def test_uploaded_file_is_hashed_without_retaining_name_or_bytes(console):
    client, headers, requests, _, database = console
    contents = b"synthetic-private-file-contents-73928"
    digest = hashlib.sha256(contents).hexdigest()
    response = client.post("/api/admin/downloads/scan-file", headers=headers,
                           data={"device_id": "analyst", "device_name": "Review station"},
                           files={"file": ("private-filename-73928.bin", contents)})
    assert response.status_code == 201
    assert requests[0].url.path.endswith(digest)
    assert requests[0].content == b""
    with sqlite3.connect(database) as connection:
        stored = "\n".join(connection.iterdump())
    assert "private-filename-73928" not in stored
    assert contents.decode() not in stored


@pytest.mark.parametrize("metadata", [
    {"device_id": "../invalid", "device_name": "Test"},
    {"device_id": "test", "device_name": "x" * 121},
    {"device_id": "test", "device_name": "Test", "extension_key": "bad/key"},
])
def test_invalid_upload_metadata_is_validation_error_not_server_error(console, metadata):
    client, headers, requests, _, _ = console
    response = client.post("/api/admin/downloads/scan-file", headers=headers, data=metadata,
                           files={"file": ("sample.bin", b"sample")})
    assert response.status_code == 422
    assert requests == []


def test_alert_lifecycle_is_audited_and_counts_stay_consistent(console):
    client, headers, _, notifications, _ = console
    scan = create_threat(client)
    alert = client.get("/api/alerts", headers=headers).json()[0]
    route = f"/api/alerts/{alert['id']}/status"
    previous = "open"
    for status, pending in (("acknowledged", 1), ("resolved", 0), ("open", 1)):
        response = client.post(route, headers=headers, json={"status": status, "expected_status": previous,
                                                            "reason": "Reviewed the available evidence"})
        assert response.status_code == 200, response.text
        assert response.json() == {"id": alert["id"], "status": status, "changed": True}
        overview = client.get("/api/overview", headers=headers).json()
        assert overview["pending_alerts"] == pending
        assert overview["open_alerts"] == int(status == "open")
        previous = status
    duplicate = client.post(route, headers=headers, json={"status": "open", "reason": "Reviewed the evidence"})
    assert duplicate.json()["changed"] is False
    events = client.get(f"/api/scans/{scan['id']}", headers=headers).json()["events"]
    changes = [event for event in events if event["event_type"] == "alert_status_changed"]
    assert len(changes) == 3
    assert all(event["actor"] == "analyst" and event["reason"] for event in changes)
    assert all(event["alert_id"] == alert["id"] for event in changes)
    assert len(notifications) == 1  # Triage never resends a threat notification.


def test_concurrent_triage_rejects_stale_change(console):
    client, headers, _, _, _ = console
    create_threat(client)
    alert = client.get("/api/alerts", headers=headers).json()[0]
    route = f"/api/alerts/{alert['id']}/status"

    def change(status):
        return client.post(route, headers=headers, json={"status": status, "expected_status": "open",
                                                        "reason": "Concurrent reviewer decision"}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(change, ("acknowledged", "resolved")))
    assert sorted(statuses) == [200, 409]
    changes = [event for event in client.get("/api/events", headers=headers).json()
               if event["event_type"] == "alert_status_changed"]
    assert len(changes) == 1


def test_suppressed_alert_cannot_be_reopened(console):
    client, headers, _, notifications, _ = console
    assert client.post("/api/overrides", headers=headers,
                       json={"kind": "domain", "target": "example.invalid", "reason": "Approved testing domain"}).status_code == 201
    create_threat(client)
    alert = client.get("/api/alerts", headers=headers).json()[0]
    assert alert["status"] == "suppressed"
    response = client.post(f"/api/alerts/{alert['id']}/status", headers=headers,
                           json={"status": "open", "reason": "Attempt to reopen suppressed"})
    assert response.status_code == 409
    assert notifications == []


def test_triage_validation_and_missing_records(console):
    client, headers, _, _, _ = console
    create_threat(client)
    alert = client.get("/api/alerts", headers=headers).json()[0]
    route = f"/api/alerts/{alert['id']}/status"
    for reason in ("        ", "short", "x" * 501):
        assert client.post(route, headers=headers, json={"status": "resolved", "reason": reason}).status_code == 422
    assert client.post(route, headers=headers, json={"status": "deleted", "reason": "Invalid state requested"}).status_code == 422
    assert client.post("/api/alerts/missing/status", headers=headers,
                       json={"status": "resolved", "reason": "Reviewed the evidence"}).status_code == 404
    assert client.get("/api/scans/missing", headers=headers).status_code == 404


def test_scan_evidence_explains_score_and_unknowns_without_private_url(console):
    client, headers, _, _, _ = console
    scan = create_threat(client)
    detail = client.get(f"/api/scans/{scan['id']}", headers=headers).json()
    policy = client.get("/api/risk-policy", headers=headers).json()
    assert detail["risk_policy_version"] == policy["version"]
    assert detail["score"] == 80 and detail["completeness"] == "partial"
    assert detail["unknown_codes"] == ["new_domain"]
    assert detail["findings"][0]["points"] == 80
    assert detail["suggested_action"]
    assert "private-record" not in json.dumps(detail)
    assert "private-token" not in json.dumps(detail)
    assert policy["score_cap"] == 100


def test_activity_timeline_has_fourteen_utc_days_and_excludes_old_scans(console):
    client, headers, _, _, _ = console
    first = create_threat(client)
    create_threat(client)
    with client.app.state.session_factory() as db:
        old = db.get(Scan, first["id"])
        old.created_at = datetime.now(timezone.utc) - timedelta(days=30)
        db.commit()
    overview = client.get("/api/overview", headers=headers).json()
    assert len(overview["daily_activity"]) == 14
    assert overview["daily_activity"][-1]["date"] == datetime.now(timezone.utc).date().isoformat()
    assert sum(day["scans"] for day in overview["daily_activity"]) == 1
    assert sum(day["high_risk"] for day in overview["daily_activity"]) == 1
    assert overview["total_scans"] == 2


def test_logout_revokes_access_to_new_admin_actions(console):
    client, headers, requests, _, _ = console
    assert client.post("/api/admin/logout", headers=headers).status_code == 200
    assert client.get("/api/risk-policy", headers=headers).status_code == 401
    assert client.post("/api/admin/downloads/scan", headers=headers,
                       json={"device_id": "test", "device_name": "Test", "sha256": "f" * 64}).status_code == 401
    assert requests == []


def test_password_and_totp_attempts_share_client_limit_and_ignore_forwarded_headers(console):
    client, _, _, _, _ = console
    responses = []
    # The fixture's successful password and TOTP steps already consumed two attempts.
    for index in range(20):
        responses.append(client.post("/api/admin/login",
                                     headers={"X-Forwarded-For": f"192.0.2.{index}"},
                                     json={"username": "unknown-account", "password": "incorrect"}))
    assert sum(response.status_code == 429 for response in responses) == 2
    limited = client.post("/api/admin/verify", json={"challenge_token": "fake", "totp_code": "000000"})
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 60


def test_international_hostname_display_matches_browser_domain(console):
    client, _, _, _, _ = console
    response = client.post("/api/scans", headers=INGEST, json={
        "device_id": "test", "device_name": "Test", "target_kind": "url", "target": "https://faß.de/test",
        "signals": [{"code": "malicious_url", "status": "clear"}],
    })
    assert response.status_code == 201
    assert response.json()["target_display"] == "xn--fa-hia.de"


def test_low_risk_evidence_does_not_claim_no_findings(console):
    client, headers, _, _, _ = console
    response = client.post("/api/scans", headers=INGEST, json={
        "device_id": "test", "device_name": "Test", "target_kind": "extension", "target": "sample-extension",
        "signals": [{"code": "sensitive_permission", "status": "detected"}],
    })
    assert response.status_code == 201
    evidence = client.get(f"/api/scans/{response.json()['id']}", headers=headers).json()
    assert evidence["severity"] == "Low"
    assert "detected indicators" in evidence["suggested_action"]


def test_non_ascii_ingest_header_is_rejected_without_server_error(console):
    client, _, _, _, _ = console
    response = client.post("/api/scans", headers={"X-Ingest-Token": b"\xff"}, json={
        "device_id": "test", "device_name": "Test", "target_kind": "url", "target": "https://example.invalid/",
        "signals": [],
    })
    assert response.status_code == 401
