import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.report_schema import SCHEMA_VERSION, validate_report


class TestReportSchema(unittest.TestCase):
    def test_valid_minimal_audit_report(self):
        report = {
            "schema_version": SCHEMA_VERSION,
            "target": "localhost",
            "results": [{"tool": "nmap", "success": True, "command": "nmap localhost"}],
            "started_at": 1.0,
            "finished_at": 2.0,
        }
        ok, errors = validate_report(report, kind="audit")
        self.assertTrue(ok)
        self.assertEqual(errors, [])

    def test_invalid_report_missing_target(self):
        report = {"schema_version": SCHEMA_VERSION, "results": []}
        ok, errors = validate_report(report, kind="audit")
        self.assertFalse(ok)
        self.assertTrue(any("target is required" in e for e in errors))

    def test_react_kind_requires_react_block(self):
        report = {"schema_version": SCHEMA_VERSION, "target": "t", "results": []}
        ok, errors = validate_report(report, kind="react")
        self.assertFalse(ok)
        self.assertTrue(any(e == "react is required for react reports" for e in errors))


if __name__ == "__main__":
    unittest.main()

