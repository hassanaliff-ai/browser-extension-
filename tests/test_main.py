import pytest
from httpx import Response

from tests.helpers import VT_BASE, analysis_payload, object_payload, url_id

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
RESPONSE_KEYS = {
    "target",
    "scan_type",
    "verdict",
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "cached",
}


def scan(client, target, scan_type="url"):
    return client.post("/scan", json={"target": target, "scan_type": scan_type})


class TestHealth:
    @pytest.mark.parametrize("path", ["/", "/health"])
    def test_health_endpoints(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "ExtSecure API"}

    def test_feature_discovery_is_explicit_when_monitoring_is_not_configured(self, client):
        response=client.get('/extension/capabilities')
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        assert response.json()=={'api_version':'0.4.1','monitoring_available':False,'monitoring_base':None,
            'monitoring_docs':None,'capabilities':[],'workflow_runner_started':False}


class TestScanShape:
    def test_url_scan(self, client, respx_mock):
        respx_mock.get(f"{VT_BASE}/urls/{url_id('https://google.com')}").mock(
            return_value=Response(200, json=object_payload(harmless=70, undetected=20))
        )

        response = scan(client, "https://google.com", "url")

        assert response.status_code == 200
        assert response.json() == {
            "target": "https://google.com",
            "scan_type": "url",
            "verdict": "harmless",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 70,
            "undetected": 20,
            "cached": False,
        }

    def test_hash_scan(self, client, respx_mock):
        respx_mock.get(f"{VT_BASE}/files/{SHA256}").mock(
            return_value=Response(200, json=object_payload(malicious=66, undetected=2))
        )

        response = scan(client, SHA256, "hash")

        assert response.status_code == 200
        assert response.json() == {
            "target": SHA256,
            "scan_type": "hash",
            "verdict": "malicious",
            "malicious": 66,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 2,
            "cached": False,
        }

    def test_ip_scan(self, client, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(
            return_value=Response(200, json=object_payload(harmless=52, undetected=37))
        )

        response = scan(client, "8.8.8.8", "ip")

        assert response.status_code == 200
        assert response.json() == {
            "target": "8.8.8.8",
            "scan_type": "ip",
            "verdict": "harmless",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 52,
            "undetected": 37,
            "cached": False,
        }

    def test_scan_type_defaults_to_url(self, client, respx_mock):
        route = respx_mock.get(f"{VT_BASE}/urls/{url_id('https://google.com')}").mock(
            return_value=Response(200, json=object_payload(harmless=1))
        )

        response = client.post("/scan", json={"target": "https://google.com"})

        assert response.status_code == 200
        assert response.json()["scan_type"] == "url"
        assert route.call_count == 1

    @pytest.mark.parametrize(
        ("counts", "verdict"),
        [
            ({"malicious": 2, "harmless": 61}, "suspicious"),
            ({"malicious": 3}, "malicious"),
            ({"suspicious": 3}, "suspicious"),
            ({"suspicious": 2}, "harmless"),
        ],
    )
    def test_verdict_thresholds_apply_but_raw_counts_are_untouched(
        self, client, respx_mock, counts, verdict
    ):
        respx_mock.get(f"{VT_BASE}/ip_addresses/1.2.3.4").mock(
            return_value=Response(200, json=object_payload(**counts))
        )

        body = scan(client, "1.2.3.4", "ip").json()

        assert set(body) == RESPONSE_KEYS
        assert body["verdict"] == verdict
        for name, value in counts.items():
            assert body[name] == value


class TestCache:
    def test_second_identical_request_is_served_from_cache(self, client, respx_mock):
        route = respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(
            return_value=Response(200, json=object_payload(harmless=52))
        )

        first = scan(client, "8.8.8.8", "ip")
        second = scan(client, "8.8.8.8", "ip")

        assert first.json()["cached"] is False
        assert second.json()["cached"] is True
        assert route.call_count == 1
        assert {**second.json(), "cached": False} == first.json()

    def test_different_targets_are_not_shared(self, client, respx_mock):
        first = respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(
            return_value=Response(200, json=object_payload(harmless=1))
        )
        second = respx_mock.get(f"{VT_BASE}/ip_addresses/1.1.1.1").mock(
            return_value=Response(200, json=object_payload(harmless=1))
        )

        assert scan(client, "8.8.8.8", "ip").json()["cached"] is False
        assert scan(client, "1.1.1.1", "ip").json()["cached"] is False
        assert (first.call_count, second.call_count) == (1, 1)

    def test_errors_are_not_cached(self, client, respx_mock):
        route = respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(
            side_effect=[
                Response(429),
                Response(200, json=object_payload(harmless=52)),
            ]
        )

        assert scan(client, "8.8.8.8", "ip").status_code == 429
        retry = scan(client, "8.8.8.8", "ip")

        assert retry.status_code == 200
        assert retry.json()["cached"] is False
        assert route.call_count == 2


class TestSubmitAndPoll:
    def test_unknown_url_is_submitted_polled_and_returned(self, client, respx_mock):
        url = "https://example.com/?t=never-seen"
        lookup = respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        submit = respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-1"}})
        )
        poll = respx_mock.get(f"{VT_BASE}/analyses/analysis-1").mock(
            side_effect=[
                Response(200, json=analysis_payload("queued")),
                Response(200, json=analysis_payload("completed", harmless=62, undetected=28)),
            ]
        )

        response = scan(client, url)

        assert response.status_code == 200
        assert response.json() == {
            "target": url,
            "scan_type": "url",
            "verdict": "harmless",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 62,
            "undetected": 28,
            "cached": False,
        }
        assert (lookup.call_count, submit.call_count, poll.call_count) == (1, 1, 2)

        again = scan(client, url)
        assert again.json()["cached"] is True
        assert (lookup.call_count, submit.call_count, poll.call_count) == (1, 1, 2)

    def test_analysis_that_never_completes_returns_504(self, client, respx_mock):
        url = "https://example.com/?t=slow"
        respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-2"}})
        )
        respx_mock.get(f"{VT_BASE}/analyses/analysis-2").mock(
            return_value=Response(200, json=analysis_payload("queued"))
        )

        response = scan(client, url)

        assert response.status_code == 504
        assert "did not finish" in response.json()["detail"]


class TestErrorMapping:
    @pytest.mark.parametrize(
        ("vt_status", "expected_status"),
        [
            (401, 502),
            (403, 502),
            (404, 404),
            (429, 429),
            (400, 422),
            (500, 502),
            (503, 502),
        ],
    )
    def test_vt_status_maps_to_http_status(self, client, respx_mock, vt_status, expected_status):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(return_value=Response(vt_status))

        response = scan(client, "8.8.8.8", "ip")

        assert response.status_code == expected_status
        assert isinstance(response.json()["detail"], str)

    def test_rate_limit_sets_retry_after(self, client, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(return_value=Response(429))

        response = scan(client, "8.8.8.8", "ip")

        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"

    @pytest.mark.parametrize("vt_status", [401, 404, 500])
    def test_other_errors_do_not_set_retry_after(self, client, respx_mock, vt_status):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(return_value=Response(vt_status))
        assert "retry-after" not in scan(client, "8.8.8.8", "ip").headers

    def test_bad_api_key_does_not_leak_the_key(self, client, respx_mock):
        respx_mock.get(f"{VT_BASE}/ip_addresses/8.8.8.8").mock(return_value=Response(401))

        response = scan(client, "8.8.8.8", "ip")

        assert response.status_code == 502
        assert "test-key" not in response.text

    def test_unknown_hash_returns_404(self, client, respx_mock):
        respx_mock.get(f"{VT_BASE}/files/{SHA256}").mock(return_value=Response(404))
        assert scan(client, SHA256, "hash").status_code == 404

    def test_404_after_submit_returns_404(self, client, respx_mock):
        url = "https://example.com/?t=vanished"
        respx_mock.get(f"{VT_BASE}/urls/{url_id(url)}").mock(return_value=Response(404))
        respx_mock.post(f"{VT_BASE}/urls").mock(
            return_value=Response(200, json={"data": {"id": "analysis-3"}})
        )
        respx_mock.get(f"{VT_BASE}/analyses/analysis-3").mock(return_value=Response(404))

        assert scan(client, url).status_code == 404


class TestValidation:
    @pytest.mark.parametrize("scan_type", ["file", "domain", "URL", "", None, 5])
    def test_invalid_scan_type_is_422_and_never_reaches_vt(self, client, respx_mock, scan_type):
        response = client.post("/scan", json={"target": "https://google.com", "scan_type": scan_type})

        assert response.status_code == 422
        assert respx_mock.calls.call_count == 0

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"scan_type": "url"},
            {"target": ""},
            {"target": None},
            {"target": 123},
            {"target": ["https://google.com"]},
        ],
    )
    def test_bad_body_is_422_and_never_reaches_vt(self, client, respx_mock, payload):
        assert client.post("/scan", json=payload).status_code == 422
        assert respx_mock.calls.call_count == 0

    def test_non_json_body_is_422(self, client, respx_mock):
        response = client.post("/scan", content="target=x", headers={"content-type": "text/plain"})
        assert response.status_code == 422
        assert respx_mock.calls.call_count == 0

    @pytest.mark.parametrize(
        ("target", "scan_type"),
        [
            ("not-a-hash", "hash"),
            ("abc123", "hash"),
            ("g" * 64, "hash"),
            ("not-an-ip", "ip"),
            ("999.1.1.1", "ip"),
            ("8.8.8.8/../x", "ip"),
            ("google.com", "url"),
            ("ftp://example.com", "url"),
            ("javascript:alert(1)", "url"),
        ],
    )
    def test_malformed_target_is_422_and_never_reaches_vt(
        self, client, respx_mock, target, scan_type
    ):
        response = scan(client, target, scan_type)

        assert response.status_code == 422
        assert respx_mock.calls.call_count == 0

    def test_hash_target_sent_as_ip_is_rejected(self, client, respx_mock):
        assert scan(client, SHA256, "ip").status_code == 422
        assert respx_mock.calls.call_count == 0


class TestCors:
    def test_extension_origin_preflight_is_allowed(self, client):
        response = client.options(
            "/scan",
            headers={
                "Origin": "chrome-extension://abcdefghijklmnop",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "*"
