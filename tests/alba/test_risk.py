"""Risk decisions that should remain stable across extension and dashboard use."""

import unittest

from pydantic import ValidationError

from alba_security.risk import SignalInput, assess


class RiskAssessmentTests(unittest.TestCase):
    def test_fixed_weights_and_detected_findings(self):
        cases = {
            "sensitive_permission": 20,
            "broad_host_access": 15,
            "obfuscated_code": 25,
            "external_data_transfer": 25,
            "malicious_url": 80,
            "suspicious_url": 30,
            "new_domain": 15,
            "malicious_file_hash": 90,
        }
        for code, points in cases.items():
            with self.subTest(code=code):
                result = assess(
                    [SignalInput(code=code, status="detected", detail="Observed evidence")]
                )
                self.assertEqual(result.score, points)
                self.assertEqual(result.completeness, "complete")
                self.assertEqual(len(result.findings), 1)
                self.assertEqual(result.findings[0].code, code)
                self.assertEqual(result.findings[0].detail, "Observed evidence")
                self.assertEqual(result.findings[0].points, points)
                self.assertTrue(result.findings[0].title)
                self.assertEqual(result.unknown_codes, [])

    def test_severity_thresholds_and_score_cap(self):
        cases = [
            ([], 0, "Low"),
            (["sensitive_permission"], 20, "Low"),
            (["suspicious_url"], 30, "Medium"),
            (["suspicious_url", "obfuscated_code"], 55, "Medium"),
            (["sensitive_permission", "broad_host_access", "obfuscated_code"], 60, "High"),
            (["suspicious_url", "obfuscated_code", "sensitive_permission"], 75, "High"),
            (["malicious_url"], 80, "Critical"),
            (["malicious_file_hash", "malicious_url"], 100, "Critical"),
        ]
        for codes, expected_score, expected_severity in cases:
            with self.subTest(codes=codes):
                signals = [SignalInput(code=code, status="detected") for code in codes]
                if not signals:
                    # A verified clear result is assessable, unlike a missing result.
                    signals = [SignalInput(code="new_domain", status="clear")]
                result = assess(signals)
                self.assertEqual(result.score, expected_score)
                self.assertEqual(result.severity, expected_severity)

    def test_missing_or_failed_checks_never_look_clear(self):
        empty = assess([])
        failed = assess([SignalInput(code="malicious_url", status="unknown")])

        for result in (empty, failed):
            self.assertIsNone(result.score)
            self.assertEqual(result.severity, "Unknown")
            self.assertEqual(result.completeness, "unknown")
            self.assertEqual(result.findings, [])
        self.assertEqual(failed.unknown_codes, ["malicious_url"])

    def test_partial_result_preserves_unknown_check_and_confirmed_score(self):
        result = assess(
            [
                SignalInput(code="suspicious_url", status="detected"),
                SignalInput(code="malicious_file_hash", status="unknown"),
                SignalInput(code="new_domain", status="clear"),
            ]
        )

        self.assertEqual(result.score, 30)
        self.assertEqual(result.severity, "Medium")
        self.assertEqual(result.completeness, "partial")
        self.assertEqual(result.unknown_codes, ["malicious_file_hash"])
        self.assertEqual([finding.code for finding in result.findings], ["suspicious_url"])
        self.assertTrue(result.findings[0].detail)

    def test_duplicate_code_is_rejected_even_with_different_statuses(self):
        with self.assertRaisesRegex(ValueError, "Duplicate risk signal: malicious_url"):
            assess(
                [
                    SignalInput(code="malicious_url", status="clear"),
                    SignalInput(code="malicious_url", status="detected"),
                ]
            )

    def test_caller_cannot_supply_weights_or_unrecognized_signals(self):
        with self.assertRaises(ValidationError):
            SignalInput.model_validate(
                {"code": "new_domain", "status": "detected", "points": 100}
            )
        with self.assertRaises(ValidationError):
            SignalInput(code="unlisted_signal", status="detected")
        with self.assertRaises(ValidationError):
            SignalInput(code="malicious_url", status="probably_safe")


if __name__ == "__main__":
    unittest.main()
