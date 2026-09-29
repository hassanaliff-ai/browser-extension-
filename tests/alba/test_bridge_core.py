"""Core contract used by the public VirusTotal bridge."""

from datetime import datetime, timezone

import pytest
from argon2 import PasswordHasher
from fastapi import HTTPException
from sqlalchemy import func, select

from alba_security.admin_auth import AdminAuth
from alba_security.api import ScanCreate, _target_identity, create_app
from alba_security.models import Alert, Scan, SecurityEvent
from alba_security.reports import aggregate_month
from alba_security.risk import SignalInput, assess


def test_ip_and_hash_targets_are_validated_and_normalized():
    first_ip = _target_identity("ip", "2001:0DB8::1")
    second_ip = _target_identity("ip", "2001:db8::1")
    assert first_ip == second_ip
    assert first_ip[1].startswith("IPv6 ")
    assert "2001:db8" not in first_ip[1]

    for length, algorithm in ((32, "MD5"), (40, "SHA-1"), (64, "SHA-256")):
        digest = "A" * length
        fingerprint, display = _target_identity("hash", digest)
        assert len(fingerprint) == 64
        assert display == f"{algorithm} {'a' * 12}…"
        assert _target_identity("hash", digest.lower())[0] == fingerprint

    for kind, target in (("ip", "not-an-ip"), ("hash", "abc"), ("download", "a" * 32)):
        with pytest.raises(HTTPException) as error:
            _target_identity(kind, target)
        assert error.value.status_code == 422


@pytest.mark.parametrize("code,points,severity", [
    ("malicious_ip", 80, "Critical"),
    ("suspicious_ip", 30, "Medium"),
])
def test_ip_signals_have_fixed_risk_weights(code, points, severity):
    result = assess([SignalInput(code=code, status="detected")])
    assert result.score == points
    assert result.severity == severity


def test_bridge_records_ip_and_hash_without_external_delivery(tmp_path):
    deliveries = []
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'bridge.sqlite3').as_posix()}",
        ingest_token="test-ingest-secret",
        admin_auth=AdminAuth(
            username="test-admin",
            password_hash=PasswordHasher().hash("test-password"),
            totp_secret="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        ),
        alert_notifier=lambda **kwargs: deliveries.append(kwargs) or [],
    )

    with app.state.session_factory() as db:
        ip_result = app.state.record_scan(ScanCreate(
            device_id="browser-device", device_name="Browser",
            target_kind="ip", target="192.0.2.4",
            signals=[SignalInput(code="malicious_ip", status="detected")],
        ), db, notify=False)
        hash_result = app.state.record_scan(ScanCreate(
            device_id="browser-device", device_name="Browser",
            target_kind="hash", target="a" * 32,
            signals=[SignalInput(code="malicious_file_hash", status="unknown")],
        ), db, notify=False)

    assert ip_result["severity"] == "Critical"
    assert ip_result["target_kind"] == "ip"
    assert hash_result["severity"] == "Unknown"
    assert hash_result["target_kind"] == "hash"
    assert deliveries == []

    with app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(Alert)) == 1
        assert db.scalar(select(func.count()).select_from(SecurityEvent).where(
            SecurityEvent.event_type == "notification_delivery"
        )) == 0
        scans = db.scalars(select(Scan)).all()
        assert {scan.target_kind for scan in scans} == {"ip", "hash"}
        assert all(scan.target_display != "192.0.2.4" for scan in scans)
        now = datetime.now(timezone.utc)
        stats = aggregate_month(db, now.year, now.month)
        assert stats["target_kind_counts"]["ip"] == 1
        assert stats["target_kind_counts"]["hash"] == 1

