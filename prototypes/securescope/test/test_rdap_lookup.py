import unittest
from datetime import datetime, timezone

from backend.rdap_lookup import lookup_domain_age


BOOTSTRAP = {"services": [
    [["com"], ["http://insecure.example/", "https://rdap.example/com/"]],
    [["co.uk"], ["https://rdap.example/uk/"]],
]}


class RdapLookupTests(unittest.TestCase):
    def test_registration_age_and_longest_suffix(self):
        urls = []

        def fetch(url):
            urls.append(url)
            return {"objectClassName": "domain", "ldhName": "EXAMPLE.CO.UK",
                    "events": [{"eventAction": "registration", "eventDate": "2026-09-01T00:00:00Z"}]}

        result = lookup_domain_age("example.co.uk", fetch_json=fetch,
                                   bootstrap=BOOTSTRAP,
                                   now=datetime(2026, 9, 30, tzinfo=timezone.utc))
        self.assertEqual(urls, ["https://rdap.example/uk/domain/example.co.uk"])
        self.assertEqual(result["status"], "Known")
        self.assertEqual(result["age_days"], 29)

    def test_missing_registration_is_unknown(self):
        result = lookup_domain_age("example.com", bootstrap=BOOTSTRAP,
                                   fetch_json=lambda _: {"objectClassName": "domain",
                                                         "ldhName": "example.com", "events": []})
        self.assertEqual(result["status"], "Unknown")

    def test_conflicting_registration_dates_are_unknown(self):
        result = lookup_domain_age(
            "example.com", bootstrap=BOOTSTRAP,
            fetch_json=lambda _: {
                "objectClassName": "domain", "ldhName": "example.com",
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"},
                ],
            },
            now=datetime(2026, 9, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(result["status"], "Unknown")
        self.assertIn("conflicting", result["reason"])

    def test_duplicate_equivalent_registration_dates_are_known(self):
        result = lookup_domain_age(
            "example.com", bootstrap=BOOTSTRAP,
            fetch_json=lambda _: {
                "objectClassName": "domain", "ldhName": "example.com",
                "events": [
                    {"eventAction": "registration", "eventDate": "2026-09-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2026-09-01T03:00:00+03:00"},
                ],
            },
            now=datetime(2026, 9, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(result["status"], "Known")
        self.assertEqual(result["age_days"], 29)

    def test_failure_is_unknown(self):
        def fail(_):
            raise TimeoutError()
        result = lookup_domain_age("example.com", bootstrap=BOOTSTRAP, fetch_json=fail)
        self.assertEqual(result["status"], "Unknown")

    def test_invalid_inputs_do_not_make_requests(self):
        for value in ("https://example.com/path", "127.0.0.1", "example.com:443", "x", "a..com"):
            self.assertEqual(lookup_domain_age(value, bootstrap=BOOTSTRAP)["status"], "Unknown")

    def test_unlisted_tld_is_unknown(self):
        result = lookup_domain_age("example.unknown", bootstrap=BOOTSTRAP)
        self.assertEqual(result["status"], "Unknown")


if __name__ == "__main__":
    unittest.main()
