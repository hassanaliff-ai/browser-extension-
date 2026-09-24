import httpx
import pytest
from httpx import Response

from app.services.virustotal import (
    AnalysisTimeoutError,
    InvalidAPIKeyError,
    InvalidTargetError,
    NotFoundError,
    RateLimitError,
    UpstreamError,
    VirusTotalClient,
    verdict_from_stats,
)
from tests.helpers import VT_BASE, analysis_payload, object_payload, url_id

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
GOOGLE = "https://google.com"


@pytest.mark.parametrize(
    ("stats", "expected"),
    [
        ({}, "harmless"),
        ({"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20}, "harmless"),
        ({"malicious": 1}, "suspicious"),
        ({"malicious": 2}, "suspicious"),
        ({"malicious": 3}, "malicious"),
        ({"malicious": 4}, "malicious"),
        ({"malicious": 66}, "malicious"),
        ({"suspicious": 1}, "harmless"),
        ({"suspicious": 2}, "harmless"),
        ({"suspicious": 3}, "suspicious"),
        ({"suspicious": 40}, "suspicious"),
        ({"malicious": 2, "suspicious": 5}, "suspicious"),
        ({"malicious": 3, "suspicious": 5}, "malicious"),
        ({"malicious": 0, "suspicious": 2, "harmless": 0, "undetected": 90}, "harmless"),
    ],
)
def test_verdict_from_stats(stats, expected):
    assert verdict_from_stats(stats) == expected


@pytest.fixture
async def vt():
    client = VirusTotalClient(
        "test-key",
        poll_initial_delay=0.001,
        poll_max_delay=0.005,
        poll_timeout=0.2,
    )
    yield client
    await client.aclose()


@pytest.mark.anyio
class TestScanUrl:
    async def test_known_url_uses_encoded_id_and_api_key(self, vt, respx_mock):
        # Known vector: base64url of "https://google.com" with padding stripped.
        route = respx_mock.get(f"{VT_BASE}/urls/aHR0cHM6Ly9nb29nbGUuY29t").mock(
            return_value=Response(200, json=object_payload(malicious=2, harmless=61, undetected=27))
        )

        result = await vt.scan_url(GOOGLE)

        assert route.call_count == 1
        assert route.calls.last.request.headers["x-apikey"] == "test-key"
        assert (result.verdict, result.malicious, result.harmless, result.undetected) == (
            "suspicious",
            2,
            61,
            27,
        )
        assert (result.target, result.scan_type) == (GOOGLE, "url")

    async def test_unknown_url_is_submitted_then_polled_until_completed(self, vt, respx_mock):
        url = "https://example.com/?t=never-seen"
        lookup = respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        submit = respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-1"}})
        )
        poll = respx_mock.get(f"{VT_BASE}/analyses/analysis-1").mock(
            side_effect=[
                Response(200, json=analysis_payload("queued")),
                Response(200, json=analysis_payload("in-progress")),
                Response(200, json=analysis_payload("completed", malicious=5, harmless=60)),
            ]
        )

        result = await vt.scan_url(url)

        assert lookup.call_count == 1
        assert submit.call_count == 1
        assert b"url=" in submit.calls.last.request.content
        assert poll.call_count == 3
        assert (result.verdict, result.malicious, result.harmless) == ("malicious", 5, 60)

    async def test_poll_that_never_completes_times_out(self, vt, respx_mock):
        url = "https://example.com/?t=slow"
        respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-2"}})
        )
        respx_mock.get(f"{VT_BASE}/analyses/analysis-2").mock(
            return_value=Response(200, json=analysis_payload("queued"))
        )

        with pytest.raises(AnalysisTimeoutError):
            await vt.scan_url(url)

    async def test_404_on_analysis_after_submit_raises_not_found(self, vt, respx_mock):
        url = "https://example.com/?t=vanished"
        respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-3"}})
        )
        respx_mock.get(f"{VT_BASE}/analyses/analysis-3").mock(return_value=Response(404))

        with pytest.raises(NotFoundError):
            await vt.scan_url(url)

    async def test_submission_without_analysis_id_is_upstream_error(self, vt, respx_mock):
        url = "https://example.com/?t=weird"
        respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        respx_mock.post(f"{VT_BASE}/urls").mock(return_value=Response(200, json={"data": {}}))

        with pytest.raises(UpstreamError):
            await vt.scan_url(url)

    async def test_rate_limit_during_poll_is_surfaced(self, vt, respx_mock):
        url = "https://example.com/?t=limited"
        respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-4"}})
        )
        respx_mock.get(f"{VT_BASE}/analyses/analysis-4").mock(return_value=Response(429))

        with pytest.raises(RateLimitError):
            await vt.scan_url(url)

    @pytest.mark.parametrize("bad_url", ["ftp://example.com", "google.com", "http://", "", "javascript:alert(1)"])
    async def test_invalid_url_is_rejected_without_calling_vt(self, vt, respx_mock, bad_url):
        with pytest.raises(InvalidTargetError):
            await vt.scan_url(bad_url)
        assert respx_mock.calls.call_count == 0


@pytest.mark.anyio
class TestScanHash:
    @pytest.mark.parametrize("file_hash", ["d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", SHA256.upper()])
    async def test_md5_sha1_sha256_are_accepted(self, vt, respx_mock, file_hash):
        route = respx_mock.get(f"{VT_BASE}/files/{file_hash}").mock(
            return_value=Response(200, json=object_payload(malicious=66, undetected=2))
        )

        result = await vt.scan_hash(file_hash)

        assert route.call_count == 1
        assert (result.verdict, result.scan_type, result.malicious) == ("malicious", "hash", 66)

    @pytest.mark.parametrize("bad_hash", ["not-a-hash", "abc123", "g" * 64, "", "../etc/passwd", SHA256 + "0"])
    async def test_invalid_hash_is_rejected_without_calling_vt(self, vt, respx_mock, bad_hash):
        with pytest.raises(InvalidTargetError):
            await vt.scan_hash(bad_hash)
        assert respx_mock.calls.call_count == 0

    async def test_unknown_hash_raises_not_found(self, vt, respx_mock):
        respx_mock.get(f"{VT_BASE}/files/{SHA256}").mock(return_value=Response(404))
        with pytest.raises(NotFoundError):
            await vt.scan_hash(SHA256)


@pytest.mark.anyio
class TestScanIp:
    @pytest.mark.parametrize("ip", ["8.8.8.8", "2001:4860:4860::8888"])
    async def test_ipv4_and_ipv6_are_accepted(self, vt, respx_mock, ip):
        route = respx_mock.get(f"{VT_BASE}/ip_addresses/{ip}").mock(
            return_value=Response(200, json=object_payload(harmless=52, undetected=37))
        )

        result = await vt.scan_ip(ip)

        assert route.call_count == 1
        assert (result.verdict, result.scan_type) == ("harmless", "ip")

    @pytest.mark.parametrize("bad_ip", ["not-an-ip", "999.1.1.1", "8.8.8", "", "8.8.8.8/../x"])
    async def test_invalid_ip_is_rejected_without_calling_vt(self, vt, respx_mock, bad_ip):
        with pytest.raises(InvalidTargetError):
            await vt.scan_ip(bad_ip)
        assert respx_mock.calls.call_count == 0


@pytest.mark.anyio
class TestErrorMapping:
    @pytest.mark.parametrize(
        ("status", "exc"),
        [
            (401, InvalidAPIKeyError),
            (403, InvalidAPIKeyError),
            (404, NotFoundError),
            (429, RateLimitError),
            (400, InvalidTargetError),
            (500, UpstreamError),
            (503, UpstreamError),
        ],
    )
    async def test_http_status_maps_to_typed_exception(self, vt, respx_mock, status, exc):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(return_value=Response(status))
        with pytest.raises(exc):
            await vt.scan_ip("8.8.8.8")

    async def test_network_failure_is_upstream_error(self, vt, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(side_effect=httpx.ConnectError("boom"))
        with pytest.raises(UpstreamError):
            await vt.scan_ip("8.8.8.8")

    async def test_timeout_is_upstream_error(self, vt, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(UpstreamError):
            await vt.scan_ip("8.8.8.8")

    async def test_non_json_body_is_upstream_error(self, vt, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(
            return_value=Response(200, content=b"<html>not json</html>")
        )
        with pytest.raises(UpstreamError):
            await vt.scan_ip("8.8.8.8")

    async def test_unexpected_json_shape_is_upstream_error(self, vt, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(
            return_value=Response(200, json={"data": {"attributes": {}}})
        )
        with pytest.raises(UpstreamError):
            await vt.scan_ip("8.8.8.8")
