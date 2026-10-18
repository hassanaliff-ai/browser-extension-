"""Offline checks for origin minimization and RDAP failure handling."""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import app, registered_domain_from_origin


class RdapApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_public_suffix_extraction(self):
        self.assertEqual(
            registered_domain_from_origin("https://login.example.co.uk"),
            "example.co.uk",
        )

    def test_private_url_parts_are_rejected_before_lookup(self):
        with patch("backend.app.lookup_domain_age") as lookup:
            for origin in (
                "https://example.com/search?q=secret",
                "https://user:pass@example.com",
                "http://localhost:8000",
                "https://127.0.0.1",
            ):
                with self.subTest(origin=origin):
                    response = self.client.post("/api/v1/rdap", json={"origin": origin})
                    self.assertEqual(response.status_code, 422)
            lookup.assert_not_called()

    def test_unknown_is_preserved(self):
        with patch("backend.app.lookup_domain_age", return_value={
            "domain": "example.com", "status": "Unknown", "reason": "RDAP lookup failed"
        }) as lookup:
            response = self.client.post("/api/v1/rdap", json={"origin": "https://www.example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "Unknown")
        lookup.assert_called_once_with("example.com")


if __name__ == "__main__":
    unittest.main()
