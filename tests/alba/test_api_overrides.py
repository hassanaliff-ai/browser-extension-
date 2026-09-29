"""Administrator exceptions are audited and never erase risk evidence."""

import json
import sqlite3

import pyotp
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from alba_security.admin_auth import AdminAuth
from alba_security.api import create_app


INGEST = {"X-Ingest-Token": "ingest-test-secret"}


def _signed_in_client(tmp_path):
    secret = pyotp.random_base32()
    notifications = []

    def notifier(**kwargs):
        notifications.append(kwargs)
        return [{"channel": "email", "status": "sent"}]

    auth = AdminAuth("admin", PasswordHasher().hash("password-123"), secret)
    database_file = tmp_path / "override-api.db"
    app = create_app(
        database_url=f"sqlite:///{database_file.as_posix()}",
        ingest_token="ingest-test-secret",
        admin_auth=auth,
        alert_notifier=notifier,
    )
    client = TestClient(app)
    first = client.post("/api/admin/login", json={"username": "admin", "password": "password-123"})
    assert first.status_code == 200, first.text
    second = client.post("/api/admin/verify", json={
        "challenge_token": first.json()["challenge_token"],
        "totp_code": pyotp.TOTP(secret).now(),
    })
    assert second.status_code == 200, second.text
    admin = {"Authorization": f"Bearer {second.json()['access_token']}"}
    return client, admin, notifications, database_file


def _scan(client, url):
    response = client.post("/api/scans", json={
        "device_id": "device-1",
        "device_name": "Lab laptop",
        "target_kind": "url",
        "target": url,
        "signals": [{"code": "malicious_url", "status": "detected"}],
    }, headers=INGEST)
    assert response.status_code == 201, response.text
    return response.json()


def test_domain_exception_suppresses_delivery_but_keeps_critical_evidence(tmp_path):
    client, admin, notifications, _ = _signed_in_client(tmp_path)
    with client:
        created = client.post("/api/overrides", json={
            "kind": "domain", "target": "Example.ORG", "reason": "Approved test domain",
        }, headers=admin)
        assert created.status_code == 201, created.text
        override_id = created.json()["id"]
        scan = _scan(client, "https://example.org/unsafe/path?token=private")
        assert scan["severity"] == "Critical"
        assert scan["score"] == 80
        assert scan["override_id"] == override_id
        assert scan["findings"][0]["code"] == "malicious_url"
        assert notifications == []
        alerts = client.get("/api/alerts", headers=admin).json()
        assert alerts[0]["status"] == "suppressed"
        events = client.get("/api/events", headers=admin).json()
        assert "threat_detected" in {item["event_type"] for item in events}
        assert "notification_suppressed" in {item["event_type"] for item in events}
        assert client.get("/api/overview", headers=admin).json()["high_risk"] == 1
        assert client.get("/api/overview", headers=admin).json()["open_alerts"] == 0

        disabled = client.post(f"/api/overrides/{override_id}/deactivate", headers=admin)
        assert disabled.status_code == 200, disabled.text
        second = _scan(client, "https://example.org/unsafe/path?token=private")
        assert second["override_id"] is None
        assert len(notifications) == 1
        assert client.get("/api/overview", headers=admin).json()["open_alerts"] == 1
        audit = client.get("/api/overrides/audit", headers=admin).json()
        assert {item["action"] for item in audit} == {"created", "deactivated"}


def test_exact_url_exception_does_not_cover_other_paths_or_store_private_url(tmp_path):
    client, admin, notifications, database_file = _signed_in_client(tmp_path)
    private_url = "https://example.org/allowed/path?private=secret-123"
    with client:
        created = client.post("/api/overrides", json={
            "kind": "url", "target": private_url, "reason": "Approved exact case",
        }, headers=admin)
        assert created.status_code == 201, created.text
        assert _scan(client, private_url)["override_id"] == created.json()["id"]
        assert _scan(client, "https://example.org/other/path")["override_id"] is None
        assert len(notifications) == 1
        visible = json.dumps([
            client.get("/api/overrides", headers=admin).json(),
            client.get("/api/overrides/audit", headers=admin).json(),
        ])
    with sqlite3.connect(database_file) as database:
        stored = "\n".join(database.iterdump())
    for fragment in ("allowed/path", "private=secret-123"):
        assert fragment not in visible
        assert fragment not in stored
