"""Monthly report API prepares factual drafts and sends them once."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pyotp
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import Session

from alba_security.admin_auth import AdminAuth
from alba_security.api import create_app
from alba_security.models import Alert, Finding, Scan, SecurityEvent
from alba_security.notifications import NotificationSettings


def test_monthly_report_generation_and_admin_delivery(tmp_path):
    secret = pyotp.random_base32()
    prompts = []
    deliveries = []

    def fake_create(**kwargs):
        prompts.append(kwargs)
        return SimpleNamespace(output_text="One critical result needs review. Check its confirmed finding and follow up with the device owner.")

    fake_llm = SimpleNamespace(responses=SimpleNamespace(create=fake_create))

    def fake_email(recipients, subject, body, _settings):
        deliveries.append((recipients, subject, body))

    settings = NotificationSettings(
        smtp_host="smtp.example.invalid", smtp_from="alerts@example.invalid",
        admin_emails=("admin@example.invalid",),
    )
    auth = AdminAuth("admin", PasswordHasher().hash("password-123"), secret)
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'reports.db').as_posix()}",
        ingest_token="ingest-test-secret",
        admin_auth=auth,
        alert_notifier=lambda **_kwargs: [],
        report_llm_client=fake_llm,
        report_model="test-summary-model",
        notification_settings=settings,
        report_email_sender=fake_email,
    )
    with TestClient(app) as client:
        login = client.post("/api/admin/login", json={"username": "admin", "password": "password-123"})
        assert login.status_code == 200, login.text
        verified = client.post("/api/admin/verify", json={
            "challenge_token": login.json()["challenge_token"],
            "totp_code": pyotp.TOTP(secret).now(),
        })
        assert verified.status_code == 200, verified.text
        admin = {"Authorization": f"Bearer {verified.json()['access_token']}"}

        scan = client.post("/api/scans", headers={"X-Ingest-Token": "ingest-test-secret"}, json={
            "device_id": "private-device-name",
            "device_name": "Private laptop",
            "target_kind": "url",
            "target": "https://example.org/private-path?token=secret",
            "signals": [{"code": "malicious_url", "status": "detected"}],
        })
        assert scan.status_code == 201, scan.text

        previous_month = datetime.now(timezone.utc).replace(day=1) - timedelta(days=1)
        recorded_at = datetime(previous_month.year, previous_month.month, 15, tzinfo=timezone.utc)
        with Session(app.state.engine) as db:
            for model in (Scan, Finding, Alert, SecurityEvent):
                db.execute(update(model).values(created_at=recorded_at))
            db.commit()

        params = {"year": previous_month.year, "month": previous_month.month}
        stats = client.get("/api/reports/monthly/stats", params=params, headers=admin)
        assert stats.status_code == 200, stats.text
        assert stats.json()["total_scans"] == 1
        assert stats.json()["high_risk_scans"] == 1
        assert stats.json()["findings_by_signal"]["malicious_url"] == 1

        generated = client.post("/api/reports/monthly/generate", json=params, headers=admin)
        assert generated.status_code == 201, generated.text
        report = generated.json()
        assert report["status"] == "draft"
        assert report["period"] == previous_month.strftime("%Y-%m")
        assert "Verified monthly statistics" in report["body"]
        assert len(prompts) == 1
        assert prompts[0]["store"] is False
        assert "private-path" not in prompts[0]["input"]
        assert "Private laptop" not in prompts[0]["input"]
        assert "private-device-name" not in prompts[0]["input"]

        again = client.post("/api/reports/monthly/generate", json=params, headers=admin)
        assert again.status_code == 201
        assert again.json()["id"] == report["id"]
        assert len(prompts) == 1

        sent = client.post(f"/api/reports/monthly/{report['period']}/send", headers=admin)
        assert sent.status_code == 200, sent.text
        assert sent.json()["status"] == "sent"
        assert sent.json()["delivery_outcomes"][0]["status"] == "sent"
        assert deliveries[0][0] == ("admin@example.invalid",)
        sent_again = client.post(f"/api/reports/monthly/{report['period']}/send", headers=admin)
        assert sent_again.status_code == 200
        assert len(deliveries) == 1
        assert len(client.get("/api/reports/monthly", headers=admin).json()) == 1


def test_current_month_cannot_be_sent_as_complete_report(tmp_path):
    secret = pyotp.random_base32()
    auth = AdminAuth("admin", PasswordHasher().hash("password-123"), secret)
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'current.db').as_posix()}",
        ingest_token="ingest-test-secret",
        admin_auth=auth,
    )
    with TestClient(app) as client:
        login = client.post("/api/admin/login", json={"username": "admin", "password": "password-123"})
        verified = client.post("/api/admin/verify", json={
            "challenge_token": login.json()["challenge_token"],
            "totp_code": pyotp.TOTP(secret).now(),
        })
        admin = {"Authorization": f"Bearer {verified.json()['access_token']}"}
        now = datetime.now(timezone.utc)
        result = client.post("/api/reports/monthly/generate", json={"year": now.year, "month": now.month}, headers=admin)
        assert result.status_code == 422
