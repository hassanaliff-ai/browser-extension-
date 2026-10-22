"""Offline checks of the extension-facing scan endpoint."""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import app
from backend.request_limits import RequestLimiter


class ScanApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.request = {"url": "https://www.example.com", "source": "visited", "checked_at": 1}

    def test_rejects_private_url_parts_before_any_lookup(self):
        with patch("backend.app._reputation") as reputation, patch("backend.app.lookup_domain_age") as rdap:
            for url in ("https://www.example.com/path?q=secret",
                        "https://user:pass@example.com", "http://127.0.0.1:8000"):
                with self.subTest(url=url):
                    response = self.client.post("/api/v1/check", json={**self.request, "url": url})
                    self.assertEqual(response.status_code, 422)
            reputation.lookup.assert_not_called()
            rdap.assert_not_called()

    def test_unavailable_reputation_is_not_low(self):
        with patch("backend.app._reputation") as reputation, patch("backend.app.lookup_domain_age") as rdap:
            reputation.lookup.return_value = {"status": "Unknown"}
            response = self.client.post("/api/v1/check", json=self.request)
            self.assertEqual(response.status_code, 503)
            rdap.assert_not_called()

    def test_only_configured_extension_may_make_cross_origin_manual_checks(self):
        extension_id = "a" * 32
        allowed_origin = f"chrome-extension://{extension_id}"
        with patch.dict("os.environ", {"SECURESCOPE_ALLOWED_EXTENSION_ID": extension_id}), \
                patch("backend.app._reputation") as reputation:
            reputation.lookup.return_value = {"status": "Unknown"}
            preflight = self.client.options("/api/v1/check", headers={
                "Origin": allowed_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            })
            self.assertEqual(preflight.status_code, 204)
            response = self.client.post("/api/v1/check", json=self.request,
                                        headers={"Origin": allowed_origin})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.headers["access-control-allow-origin"], allowed_origin)
            self.assertEqual(self.client.post("/api/v1/check", json=self.request,
                headers={"Origin": "chrome-extension://" + "b" * 32}).status_code, 403)
            self.assertEqual(self.client.post("/api/v1/rdap", json={"origin": self.request["url"]},
                headers={"Origin": allowed_origin}).status_code, 403)
            reputation.lookup.assert_called_once_with("example.com")

    def test_request_limits_cover_scan_and_rdap_without_counting_preflight(self):
        now = [100.0]
        limiter = RequestLimiter({"check": 2, "rdap": 1}, clock=lambda: now[0])
        origin = "chrome-extension://" + "a" * 32
        with patch("backend.app._request_limiter", limiter), \
                patch.dict("os.environ", {"SECURESCOPE_ALLOWED_EXTENSION_ID": "a" * 32}), \
                patch("backend.app._reputation") as reputation, \
                patch("backend.app.lookup_domain_age", return_value={"status": "Unknown"}):
            reputation.lookup.return_value = {"status": "Unknown"}
            preflight = self.client.options("/api/v1/check", headers={
                "Origin": origin, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            })
            self.assertEqual(preflight.status_code, 204)
            headers = {"Origin": origin}
            self.assertEqual(self.client.post("/api/v1/check", json=self.request,
                                              headers=headers).status_code, 503)
            self.assertEqual(self.client.post("/api/v1/check", json=self.request,
                                              headers=headers).status_code, 503)
            limited = self.client.post("/api/v1/check", json=self.request, headers=headers)
            self.assertEqual(limited.status_code, 429)
            self.assertEqual(limited.headers["retry-after"], "60")
            self.assertEqual(limited.headers["access-control-allow-origin"], origin)
            self.assertEqual(self.client.post("/api/v1/rdap", json={"origin": self.request["url"]}).status_code, 200)
            self.assertEqual(self.client.post("/api/v1/rdap", json={"origin": self.request["url"]}).status_code, 429)
            now[0] += 60
            self.assertEqual(self.client.post("/api/v1/check", json=self.request,
                                              headers=headers).status_code, 503)

    def test_rejects_unexpected_request_fields(self):
        with patch("backend.app._reputation") as reputation:
            response = self.client.post("/api/v1/check", json={**self.request, "full_url": "https://example.com/private"})
            self.assertEqual(response.status_code, 422)
            reputation.lookup.assert_not_called()

    def test_known_evidence_matches_extension_contract(self):
        reputation_result = {"status": "Known", "malicious": 2,
                             "suspicious": 0, "cached": True}
        rdap_result = {"status": "Known", "age_days": 200}
        with patch("backend.app._reputation") as reputation, patch("backend.app.lookup_domain_age", return_value=rdap_result):
            reputation.lookup.return_value = reputation_result
            response = self.client.post("/api/v1/check", json=self.request)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["origin"], self.request["url"])
        self.assertEqual(body["severity"], "High")
        self.assertEqual(body["lookup_status"], "complete")
        self.assertTrue(body["cached"])
        self.assertLessEqual(len(body["reasons"]), 10)
        self.assertTrue(all(0 < len(reason) <= 200 for reason in body["reasons"]))
        reputation.lookup.assert_called_once_with("example.com")

    def test_rdap_failure_is_partial_with_known_reputation(self):
        reputation_result = {"status": "Known", "malicious": 0,
                             "suspicious": 1, "cached": False}
        with patch("backend.app._reputation") as reputation, patch("backend.app.lookup_domain_age", return_value={"status": "Unknown"}):
            reputation.lookup.return_value = reputation_result
            response = self.client.post("/api/v1/check", json=self.request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["severity"], "Medium")
        self.assertEqual(response.json()["lookup_status"], "partial")


if __name__ == "__main__":
    unittest.main()
