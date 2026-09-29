"""Monthly reporting and outbound notification behavior without live services."""

import hashlib
import hmac
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import alba_security.overrides  # noqa: F401 — register the override table before create_all
from alba_security.models import Alert, Base, Device, Extension, Finding, Scan, SecurityEvent
from alba_security.notifications import (
    NotificationSettings,
    send_high_severity_alert,
    send_monthly_report,
)
import alba_security.notifications as notification_module
from alba_security.reports import (
    ReportConfigurationError,
    ReportGenerationError,
    aggregate_month,
    build_report_prompt,
    generate_monthly_report,
)


def stamp(month, day=1, hour=0, minute=0, second=0):
    return datetime(2026, month, day, hour, minute, second, tzinfo=timezone.utc)


@pytest.fixture
def report_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        device = Device(id="private-device-id", name="Private named device")
        extension = Extension(device_id=device.id, extension_key="extension-1", name="Private extension")
        db.add_all([device, extension])
        db.flush()

        def add_scan(created, *, severity, kind, completeness, score, display):
            scan = Scan(
                device_id=device.id,
                extension_id=extension.id,
                target_kind=kind,
                target_fingerprint="a" * 64,
                target_display=display,
                signals=[],
                score=score,
                severity=severity,
                completeness=completeness,
                created_at=created,
            )
            db.add(scan)
            db.flush()
            return scan

        add_scan(stamp(8, 31, 23, 59, 59), severity="Critical", kind="url", completeness="complete", score=90, display="before.example")
        high = add_scan(stamp(9, 1), severity="High", kind="download", completeness="complete", score=70, display="private-file-name")
        add_scan(stamp(9, 15), severity="Low", kind="extension", completeness="complete", score=0, display="private-extension")
        add_scan(stamp(9, 30, 23, 59, 59), severity="Unknown", kind="url", completeness="unknown", score=None, display="private-domain.example")
        add_scan(stamp(10, 1), severity="Critical", kind="url", completeness="complete", score=90, display="after.example")
        db.add(Finding(
            scan_id=high.id, device_id=device.id, extension_id=extension.id,
            signal_code="malicious_file_hash", title="Malicious hash", detail="private-path-or-URL",
            points=90, severity="Critical", created_at=stamp(9, 1),
        ))
        db.add(Alert(
            scan_id=high.id, severity="High", message="Threat", status="open", created_at=stamp(9, 1)
        ))
        db.add(SecurityEvent(
            event_type="threat_detected", severity="High", message="Threat",
            scan_id=high.id, device_id=device.id, extension_id=extension.id,
            details={}, created_at=stamp(9, 1),
        ))
        db.commit()
        yield db
    engine.dispose()


def test_month_aggregation_respects_utc_boundaries_and_unknown_state(report_db):
    stats = aggregate_month(report_db, 2026, 9)
    assert stats["period"] == "2026-09"
    assert stats["total_scans"] == 3
    assert stats["severity_counts"] == {
        "Unknown": 1, "Low": 1, "Medium": 0, "High": 1, "Critical": 0
    }
    assert stats["high_risk_scans"] == 1
    assert stats["target_kind_counts"] == {"url": 1, "ip": 0, "hash": 0, "extension": 1, "download": 1}
    assert stats["completeness_counts"]["unknown"] == 1
    assert stats["unique_devices"] == 1
    assert stats["unique_extensions"] == 1
    assert stats["findings_by_signal"] == {"malicious_file_hash": 1}
    assert stats["alerts_total"] == 1
    assert stats["alerts_by_status"] == {"open": 1}
    assert stats["event_counts"] == {"threat_detected": 1}


def test_llm_receives_only_aggregate_data_and_writes_report(report_db):
    calls = []

    class FakeResponses:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(output_text="Three scans were recorded. Review the high-risk file finding.")

    fake_client = SimpleNamespace(responses=FakeResponses())
    report = generate_monthly_report(report_db, 2026, 9, llm_client=fake_client, model="test-model")

    assert report["period"] == "2026-09"
    assert report["summary_source"] == "openai"
    assert "Three scans" in report["body"]
    assert "Scans: 3 | High/Critical: 1 | Unknown: 1 | Alerts: 1" in report["body"]
    assert calls[0]["model"] == "test-model"
    assert calls[0]["store"] is False
    prompt = calls[0]["input"]
    assert prompt == build_report_prompt(report["stats"])
    for private_value in ("private-device-id", "Private named device", "private-domain.example", "private-path-or-URL", "private-file-name"):
        assert private_value not in prompt

    fake_client.responses.create = lambda **_: SimpleNamespace(output_text="  ")
    with pytest.raises(ReportGenerationError):
        generate_monthly_report(report_db, 2026, 9, llm_client=fake_client, model="test-model")


def test_monthly_llm_requires_explicit_model(report_db, monkeypatch):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    with pytest.raises(ReportConfigurationError, match="OPENAI_MODEL"):
        generate_monthly_report(report_db, 2026, 9, llm_client=object())


def test_high_severity_notification_uses_every_channel_and_redacts_raw_message():
    deliveries = []
    settings = NotificationSettings(
        smtp_host="smtp.example", smtp_from="alerts@example.org",
        admin_emails=("admin@example.org",),
        webhook_urls=("https://hooks.example/one", "https://hooks.example/two"),
    )

    def email_sender(recipients, subject, body, _settings):
        deliveries.append(("email", recipients, subject, body))

    def webhook_sender(url, payload, _settings):
        deliveries.append(("webhook", url, payload))
        if url.endswith("/two"):
            raise TimeoutError("contains internal secret")

    outcomes = send_high_severity_alert(
        alert_id="alert-1", scan_id="scan-1", severity="Critical",
        message="Threat at https://private.example/path?token=secret", score=90,
        settings=settings, email_sender=email_sender, webhook_sender=webhook_sender,
    )
    assert outcomes == [
        {"channel": "email", "status": "sent"},
        {"channel": "webhook", "status": "sent", "destination_index": 1},
        {"channel": "webhook", "status": "failed", "destination_index": 2, "error_type": "TimeoutError"},
    ]
    assert "private.example" not in repr(deliveries)
    assert "secret" not in repr(outcomes)
    assert deliveries[1][2]["event"] == "high_severity_threat"
    assert send_high_severity_alert(
        alert_id="a", scan_id="s", severity="Medium", message="x", settings=settings,
        email_sender=email_sender, webhook_sender=webhook_sender,
    ) == []
    assert len(deliveries) == 3


def test_monthly_report_sends_to_admin_email_only():
    deliveries = []
    settings = NotificationSettings(
        smtp_host="smtp.example", smtp_from="reports@example.org",
        admin_emails=("admin1@example.org", "admin2@example.org"),
        webhook_urls=("https://hooks.example/alerts",),
    )
    report = {"subject": "September report", "body": "Summary and verified counts"}
    outcomes = send_monthly_report(
        report, settings=settings,
        email_sender=lambda *args: deliveries.append(args),
    )
    assert outcomes == [{"channel": "email", "status": "sent"}]
    assert deliveries[0][0] == settings.admin_emails
    assert deliveries[0][1:3] == ("September report", "Summary and verified counts")
    assert send_monthly_report(report, settings=NotificationSettings()) == [
        {"channel": "email", "status": "skipped", "reason": "not_configured"}
    ]


def test_real_adapters_use_tls_timeout_and_sign_the_exact_webhook_body(monkeypatch):
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls["smtp_connection"] = (host, port, timeout)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def starttls(self, *, context):
            calls["tls"] = context is not None

        def login(self, username, password):
            calls["login"] = (username, password)

        def send_message(self, message, *, to_addrs):
            calls["email"] = (message, to_addrs)

    class FakeHTTPClient:
        def __init__(self, *, timeout, follow_redirects):
            calls["http_settings"] = (timeout, follow_redirects)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, *, content, headers):
            calls["webhook"] = (url, content, headers)
            return SimpleNamespace(raise_for_status=lambda: None)

    monkeypatch.setattr(notification_module.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notification_module.httpx, "Client", FakeHTTPClient)
    settings = NotificationSettings(
        smtp_host="smtp.example", smtp_port=587,
        smtp_username="service-account", smtp_password="private-password",
        smtp_from="alerts@example.org", admin_emails=("admin@example.org",),
        webhook_urls=("https://hooks.example/alert",), webhook_secret="shared-secret",
        timeout_seconds=4.5,
    )
    outcomes = send_high_severity_alert(
        alert_id="a1", scan_id="s1", severity="High", message="Private URL", score=70,
        settings=settings,
    )
    assert [item["status"] for item in outcomes] == ["sent", "sent"]
    assert calls["smtp_connection"] == ("smtp.example", 587, 4.5)
    assert calls["tls"] is True
    assert calls["login"] == ("service-account", "private-password")
    assert calls["email"][1] == ["admin@example.org"]
    assert calls["http_settings"] == (4.5, False)
    _, body, headers = calls["webhook"]
    expected_digest = hmac.new(b"shared-secret", body, hashlib.sha256).hexdigest()
    assert headers["X-Alba-Signature"] == f"sha256={expected_digest}"
    assert headers["Content-Type"] == "application/json"
    assert b"Private URL" not in body

    invalid = NotificationSettings(webhook_urls=("http://hooks.example/alert",))
    assert send_high_severity_alert(
        alert_id="a1", scan_id="s1", severity="High", message="x", settings=invalid,
    )[-1] == {
        "channel": "webhook", "status": "failed", "destination_index": 1, "error_type": "ValueError"
    }


def test_invalid_notification_environment_returns_a_failure_outcome(monkeypatch):
    monkeypatch.setenv("SMTP_PORT", "not-a-number")
    assert send_high_severity_alert(
        alert_id="a1", scan_id="s1", severity="High", message="x"
    ) == [{"channel": "configuration", "status": "failed", "error_type": "ValueError"}]
