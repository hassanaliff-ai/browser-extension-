"""Provider failures, cache boundaries, and quotas cannot produce false safety."""

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from alba_security.file_lookup import FileReputationCache, VirusTotalQuota, lookup_file_hash
from alba_security.models import Base


NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[FileReputationCache.__table__, VirusTotalQuota.__table__])
    with Session(engine) as session:
        yield session
    engine.dispose()


def _report(stats):
    return httpx.Response(200, json={"data": {"id": DIGEST, "type": "file", "attributes": {"last_analysis_stats": stats}}})


@pytest.mark.parametrize("stats", [
    {"malicious": 0, "suspicious": 0, "timeout": 70},
    {"malicious": 0, "suspicious": 0, "failure": 30, "type-unsupported": 20},
    {"malicious": 0, "suspicious": 0, "unknown-new-category": 100},
    {"malicious": 0, "suspicious": 0, "harmless": True},
    {"malicious": 0, "suspicious": 0, "harmless": "70"},
    {"malicious": 0, "suspicious": 0, "harmless": -1, "undetected": 3},
    {"malicious": True, "suspicious": 0},
    {"malicious": 2**40, "suspicious": 0},
    {"malicious": 0, "suspicious": 0},
    {"harmless": 70}, [], None,
])
def test_malformed_or_incomplete_provider_analysis_is_unknown(db, stats):
    with httpx.Client(transport=httpx.MockTransport(lambda _: _report(stats))) as client:
        result = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW)
    assert result.verdict == "unknown"
    assert result.reason == "invalid_response"
    assert all(signal["status"] == "unknown" for signal in result.signals())


@pytest.mark.parametrize("response", [
    httpx.Response(200, text="not JSON"),
    httpx.Response(200, json=[]),
    httpx.Response(200, json={"data": None}),
])
def test_bad_payloads_return_unknown_without_crashing(db, response):
    with httpx.Client(transport=httpx.MockTransport(lambda _: response)) as client:
        result = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW)
    assert (result.verdict, result.reason) == ("unknown", "invalid_response")


@pytest.mark.parametrize("identity", [
    {"id": "b" * 64, "type": "file"},
    {"id": DIGEST, "type": "url"},
    {"id": DIGEST},
    {"type": "file"},
    {"id": None, "type": "file"},
    {},
])
def test_provider_report_must_identify_the_requested_file(db, identity):
    response = httpx.Response(200, json={"data": {
        **identity, "attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 20}}
    }})
    with httpx.Client(transport=httpx.MockTransport(lambda _: response)) as client:
        result = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW)
    assert (result.verdict, result.reason) == ("unknown", "invalid_response")
    assert db.get(FileReputationCache, DIGEST) is None


def test_cached_missing_report_preserves_reason_and_expires_at_boundary(db):
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(provider)) as client:
        first = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW)
        cached = lookup_file_hash(db, DIGEST.upper(), api_key="test", client=client, now=NOW + timedelta(minutes=59))
        renewed = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW + timedelta(hours=1))
    assert first.reason == cached.reason == renewed.reason == "not_found"
    assert cached.cache_hit and not renewed.cache_hit
    assert len(calls) == 2


@pytest.mark.parametrize("header,expected", [
    (" 120 ", 120), ("0", 1), ("99999", 3600), ("9" * 5000, 3600),
    ("-20", 60), ("nonsense", 60),
    (format_datetime(NOW + timedelta(seconds=150), usegmt=True), 150),
])
def test_retry_after_is_bounded_and_shared_across_hashes(db, header, expected):
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": header})

    with httpx.Client(transport=httpx.MockTransport(provider)) as client:
        result = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW)
        other = lookup_file_hash(db, "b" * 64, api_key="test", client=client, now=NOW)
    assert result.retry_after_seconds == other.retry_after_seconds == expected
    assert result.reason == other.reason == "rate_limited"
    assert len(calls) == 1


def test_quota_boundaries_reserve_failed_requests_and_reset(db):
    calls = []

    def provider(request):
        calls.append(request)
        raise httpx.ConnectError("offline", request=request)

    with httpx.Client(transport=httpx.MockTransport(provider)) as client:
        options = {"api_key": "test", "client": client, "minute_limit": 1, "day_limit": 2}
        assert lookup_file_hash(db, DIGEST, now=NOW, **options).reason == "lookup_failed"
        blocked = lookup_file_hash(db, DIGEST, now=NOW + timedelta(seconds=1), **options)
        assert blocked.reason == "rate_limited" and blocked.retry_after_seconds == 59
        assert lookup_file_hash(db, DIGEST, now=NOW + timedelta(minutes=1), **options).reason == "lookup_failed"
        assert lookup_file_hash(db, DIGEST, now=NOW + timedelta(minutes=2), **options).reason == "rate_limited"
        assert lookup_file_hash(db, DIGEST, now=NOW + timedelta(days=1), **options).reason == "lookup_failed"
    assert len(calls) == 3


@pytest.mark.parametrize("digest", [None, 123, "a" * 63, "g" * 64, "a" * 64 + "\n"])
def test_bad_hash_rejected_before_any_network_request(db, digest):
    with pytest.raises(ValueError, match="SHA-256"):
        lookup_file_hash(db, digest, api_key="test", now=NOW)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_quotas_fail_even_without_provider_config(db, limit, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(ValueError, match="quota"):
        lookup_file_hash(db, DIGEST, minute_limit=limit, now=NOW)


def test_timezone_offsets_use_utc_quota_and_cache_windows(db):
    with httpx.Client(transport=httpx.MockTransport(lambda _: _report({"malicious": 0, "suspicious": 0, "undetected": 20}))) as client:
        first = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW.astimezone(timezone(timedelta(hours=3))))
        cached = lookup_file_hash(db, DIGEST, api_key="test", client=client, now=NOW)
    assert first.verdict == cached.verdict == "clear"
    assert cached.cache_hit
