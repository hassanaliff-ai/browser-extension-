"""Offline evidence and privacy tests; these never contact VirusTotal."""

import unittest
from backend.virustotal import VirusTotalDomainClient


def report(domain="example.com", malicious=0, suspicious=0):
    return {"data": {"type": "domain", "id": domain, "attributes": {
        "last_analysis_stats": {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": 3, "undetected": 2,
        }
    }}}


class VirusTotalTests(unittest.TestCase):
    def test_requires_key_and_registered_domain_before_transport(self):
        calls = []
        client = VirusTotalDomainClient(fetch_report=lambda *args: calls.append(args))
        self.assertEqual(client.lookup("example.com")["status"], "Unknown")
        client.api_key = "test-only-key"
        for domain in ("https://example.com", "www.example.com", "127.0.0.1", "example.com/path"):
            with self.subTest(domain=domain):
                self.assertEqual(client.lookup(domain)["status"], "Unknown")
        self.assertEqual(calls, [])

    def test_domain_only_cache_and_rate_limit(self):
        calls = []
        now = [100.0]
        def fake_fetch(domain, key):
            calls.append((domain, key))
            return report(domain)
        client = VirusTotalDomainClient("test-only-key", fetch_report=fake_fetch,
                                        clock=lambda: now[0], max_per_minute=1)
        first = client.lookup("example.com")
        self.assertEqual(first["status"], "Known")
        self.assertFalse(first["cached"])
        self.assertTrue(client.lookup("example.com")["cached"])
        self.assertEqual(client.lookup("example.org")["status"], "Unknown")
        self.assertEqual(calls, [("example.com", "test-only-key")])
        now[0] += 61
        self.assertEqual(client.lookup("example.org")["status"], "Known")

    def test_mismatched_or_bad_counts_are_unknown(self):
        client = VirusTotalDomainClient("test-only-key", fetch_report=lambda *_: report("wrong.com"))
        self.assertEqual(client.lookup("example.com")["status"], "Unknown")
        client = VirusTotalDomainClient("test-only-key", fetch_report=lambda *_: report(malicious=True))
        self.assertEqual(client.lookup("example.com")["status"], "Unknown")


if __name__ == "__main__":
    unittest.main()
