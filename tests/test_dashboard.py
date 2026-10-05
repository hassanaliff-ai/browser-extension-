"""Real Streamlit execution with isolated, mocked HTTP boundaries.

These tests exercise administrator journeys, not just view helper functions.
No configured database or external reputation/email service is contacted.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from streamlit.testing.v1 import AppTest
from alba_security.permissions import profile


DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard.py"
OVERVIEW = {"total_scans": 4, "high_risk": 1, "open_alerts": 1, "pending_alerts": 2,
            "devices": 1, "extensions": 1, "severity_counts": {"Low": 2, "High": 1, "Unknown": 1},
            "daily_activity": [{"date": "2026-09-01", "scans": 4, "high_risk": 1}], "recent_events": []}


def response(data, status=200):
    return httpx.Response(status, json=data)


def expiry(minutes=20):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def button(app, label):
    return next(item for item in app.button if item.label == label)


def field(app, label):
    return next(item for item in app.text_input if item.label == label)


@pytest.fixture
def http(monkeypatch):
    def get_result(url, **kwargs):
        if url.endswith('/api/admin/me'):
            from alba_security.permissions import profile
            return response(profile('hasan', 'head_administrator'))
        if url.endswith("/api/overview"):
            return response(OVERVIEW)
        if "/api/reports/monthly/stats" in url:
            return response({"total_scans": 0, "severity_counts": {"Unknown": 0}})
        if url.endswith("/api/risk-policy"):
            return response({"version": "test-policy", "score_cap": 100, "severity_bands": [], "signals": [], "unknown_policy": "Unknown is not safe."})
        return response([])
    get = Mock(side_effect=get_result)
    post = Mock(return_value=response({"detail": "denied"}, 401))
    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr(httpx, "post", post)
    return get, post


def app(signed_in=False, view="Overview"):
    instance = AppTest.from_file(str(DASHBOARD), default_timeout=20)
    if signed_in:
        instance.session_state["admin_session_token"] = "verified-admin-token"
        instance.session_state["admin_session_expires_at"] = expiry()
        instance.session_state["workspace_view"] = view
    return instance.run()


def assert_clean(instance):
    assert not instance.exception, [item.message for item in instance.exception]


def test_unauthenticated_view_is_main_area_login_with_no_data_requests(http):
    instance = app()
    assert_clean(instance)
    assert field(instance, "Password").proto.type == 1  # Streamlit PASSWORD enum
    assert not instance.sidebar.radio
    assert not http[0].called
    assert not http[1].called


def test_password_and_totp_required_before_loading_monitoring_data(http):
    instance = app()
    http[1].return_value = response({"challenge_token": "one-step-only", "expires_at": expiry()})
    field(instance, "Username").input("operator")
    field(instance, "Password").input("test-password")
    button(instance, "Continue securely").click().run()
    assert_clean(instance)
    assert field(instance, "One-time code")
    assert not http[0].called
    assert "admin_session_token" not in instance.session_state
    http[1].return_value = response({"access_token": "verified-admin-token", "expires_at": expiry()})
    field(instance, "One-time code").input("123456")
    button(instance, "Verify and sign in").click().run()
    assert_clean(instance)
    assert instance.session_state["admin_session_token"] == "verified-admin-token"
    assert http[0].call_args.kwargs["headers"] == {"Authorization": "Bearer verified-admin-token"}
    assert "admin_challenge_token" not in instance.session_state


def test_bad_password_never_fetches_data(http):
    instance = app()
    field(instance, "Username").input("operator")
    field(instance, "Password").input("bad")
    button(instance, "Continue securely").click().run()
    assert_clean(instance)
    assert any("not accepted" in item.value for item in instance.error)
    assert not http[0].called


def test_invalid_totp_clears_challenge_and_denies_access(http):
    instance = AppTest.from_file(str(DASHBOARD))
    instance.session_state["admin_challenge_token"] = "challenge"
    instance.session_state["admin_challenge_expires_at"] = expiry()
    instance.run()
    field(instance, "One-time code").input("000000")
    button(instance, "Verify and sign in").click().run()
    assert_clean(instance)
    assert "admin_challenge_token" not in instance.session_state
    assert any("invalid or expired" in item.value for item in instance.error)
    assert not http[0].called


def test_stale_session_removes_saved_results_before_data_fetch(http):
    instance = AppTest.from_file(str(DASHBOARD))
    instance.session_state["admin_session_token"] = "stale"
    instance.session_state["admin_session_expires_at"] = expiry(-1)
    instance.session_state["download_result"] = {"severity": "Critical"}
    instance.run()
    assert_clean(instance)
    assert "download_result" not in instance.session_state
    assert field(instance, "Password")
    assert not http[0].called


def test_backend_denial_stops_entire_view_and_clears_session(http):
    http[0].side_effect = None
    http[0].return_value = response({"detail": "expired"}, 401)
    instance = app(True, "Risk levels")
    assert_clean(instance)
    assert "admin_session_token" not in instance.session_state
    assert http[0].call_count == 1  # no later policy/devices/extensions calls
    assert any("denied or expired" in item.value for item in instance.error)


@pytest.mark.parametrize("view", ["Overview", "Alerts", "Findings", "Risk levels", "Downloaded-file checks", "Scan history", "Devices", "Extensions", "Security events", "Whitelist & overrides", "Monthly reports"])
def test_each_authorized_workspace_renders_empty_and_partial_data(http, view):
    instance = app(True, view)
    assert_clean(instance)
    assert instance.sidebar.radio[0].value == view
    for call in http[0].call_args_list:
        assert call.kwargs["headers"] == {"Authorization": "Bearer verified-admin-token"}


def test_overview_counts_acknowledged_alerts_as_awaiting_review(http):
    instance = app(True)
    assert_clean(instance)
    assert next(item for item in instance.metric if item.label == "Awaiting review").value == "2"


def test_invalid_hash_clears_old_verdict_and_does_not_submit(http):
    instance = app(True, "Downloaded-file checks")
    instance.session_state["download_result"] = {"id": "old", "severity": "Low", "score": 0, "completeness": "complete"}
    field(instance, "SHA-256 hash").input("bad-hash")
    button(instance, "Check file reputation").click().run()
    assert_clean(instance)
    assert "download_result" not in instance.session_state
    assert not http[1].called
    assert any("64 hexadecimal" in item.value for item in instance.error)


def test_hash_scan_uses_admin_route_and_preserves_unknown_score(http):
    http[1].return_value = response({"id": "unknown-scan", "severity": "Unknown", "score": None,
        "completeness": "unknown", "findings": [], "file_lookup": {"verdict": "unknown", "reason": "not_found"}}, 201)
    instance = app(True, "Downloaded-file checks")
    field(instance, "SHA-256 hash").input("A" * 64)
    button(instance, "Check file reputation").click().run()
    assert_clean(instance)
    call = http[1].call_args
    assert call.args[0].endswith("/api/admin/downloads/scan")
    assert call.kwargs["headers"] == {"Authorization": "Bearer verified-admin-token"}
    assert call.kwargs["json"]["sha256"] == "a" * 64
    assert next(item for item in instance.metric if item.label == "Risk score / 100").value == "Unknown"
    assert any("incomplete" in item.value for item in instance.warning)


def test_service_failure_does_not_claim_scan_success(http):
    http[1].side_effect = httpx.ConnectError("offline")
    instance = app(True, "Downloaded-file checks")
    field(instance, "SHA-256 hash").input("a" * 64)
    button(instance, "Check file reputation").click().run()
    assert_clean(instance)
    assert instance.error
    assert not instance.success
    assert "download_result" not in instance.session_state


def test_alert_triage_requires_reason_and_sends_displayed_status(http):
    http[0].side_effect = lambda url, **kwargs: response(profile('hasan', 'head_administrator') if url.endswith('/api/admin/me') else [{"id": "alert-1", "scan_id": "scan-1", "severity": "Critical", "message": "Malicious hash", "status": "open"}])
    http[1].return_value = response({"id": "alert-1", "status": "acknowledged", "changed": True})
    instance = app(True, "Alerts")
    button(instance, "Save review").click().run()
    assert not http[1].called
    instance.text_area[0].input("Investigating this device now.")
    button(instance, "Save review").click().run()
    assert_clean(instance)
    assert http[1].call_args.kwargs["json"] == {"status": "acknowledged", "reason": "Investigating this device now.", "expected_status": "open"}


def test_conflicting_alert_review_shows_error_instead_of_success(http):
    http[0].side_effect = lambda url, **kwargs: response(profile('hasan', 'head_administrator') if url.endswith('/api/admin/me') else [{"id": "alert-1", "severity": "High", "message": "Review", "status": "open"}])
    http[1].return_value = response({"detail": "Alert changed; refresh before updating"}, 409)
    instance = app(True, "Alerts")
    instance.text_area[0].input("Investigating this device now.")
    button(instance, "Save review").click().run()
    assert_clean(instance)
    assert any("refresh" in item.value for item in instance.error)
    assert not instance.success


def test_malformed_data_shows_failure_without_fake_metrics(http):
    http[0].side_effect = None
    http[0].return_value = response("not an overview")
    instance = app(True)
    assert_clean(instance)
    assert any("unexpected data format" in item.value for item in instance.error)
    assert not instance.metric


def test_multipart_scan_uses_only_admin_session_and_discards_filename(http):
    import dashboard
    http[1].return_value = response({"id": "uploaded", "severity": "Unknown"}, 201)
    result = dashboard.post_admin("/api/admin/downloads/scan-file", "session-only",
        {"device_id": "review", "device_name": "Review"},
        upload=("download.bin", b"test bytes", "application/octet-stream"))
    assert result["id"] == "uploaded"
    call = http[1].call_args
    assert call.kwargs["headers"] == {"Authorization": "Bearer session-only"}
    assert call.kwargs["files"]["file"] == ("download.bin", b"test bytes", "application/octet-stream")
    assert "json" not in call.kwargs


def test_scan_evidence_loads_only_when_requested(http):
    scan = {"id": "scan-one", "severity": "Critical", "score": 90, "target_kind": "download", "target_display": "SHA-256 example", "completeness": "complete", "finding_codes": ["malicious_file_hash"]}
    detail = {**scan, "risk_policy_version": "policy-v1", "suggested_action": "Avoid opening the file.",
              "signals": [{"code": "malicious_file_hash", "status": "detected"}],
              "findings": [{"code": "malicious_file_hash", "title": "Malicious hash", "severity": "Critical", "points": 90, "detail": "Confirmed reputation"}], "events": []}
    http[0].side_effect = lambda url, **kwargs: response(profile('hasan', 'head_administrator') if url.endswith('/api/admin/me') else detail if url.endswith("/scan-one") else [scan])
    instance = app(True, "Scan history")
    assert all(not call.args[0].endswith("/scan-one") for call in http[0].call_args_list)
    button(instance, "Open evidence").click().run()
    assert_clean(instance)
    assert any(call.args[0].endswith("/api/scans/scan-one") for call in http[0].call_args_list)
    assert any("Avoid opening" in item.value for item in instance.markdown)


def test_report_generation_failure_keeps_draft_unsent(http):
    http[1].return_value = response({"detail": "Report summary service is not configured"}, 503)
    instance = app(True, "Monthly reports")
    button(instance, "Generate LLM draft").click().run()
    assert_clean(instance)
    assert any("not configured" in item.value for item in instance.error)
    assert not instance.success
    assert "report_notice" not in instance.session_state


def test_sign_out_revokes_session_and_removes_saved_verdict(http):
    http[1].return_value = response({"status": "signed_out"})
    instance = app(True)
    instance.session_state["download_result"] = {"severity": "Critical"}
    button(instance, "Sign out").click().run()
    assert_clean(instance)
    assert http[1].call_args.args[0].endswith("/api/admin/logout")
    assert "admin_session_token" not in instance.session_state
    assert "download_result" not in instance.session_state
    assert field(instance, "Password")
