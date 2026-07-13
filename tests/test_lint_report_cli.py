import json
import unittest
from pathlib import Path

from typer.testing import CliRunner

import supabash.__main__ as main_module


runner = CliRunner()


class TestLintReportCLI(unittest.TestCase):
    def test_valid_report_returns_zero_and_json(self):
        with runner.isolated_filesystem():
            path = Path("report.json")
            path.write_text(json.dumps({"schema_version": "1.0", "target": "localhost", "findings": [], "results": []}), encoding="utf-8")
            result = runner.invoke(main_module.app, ["lint-report", str(path), "--json"])
            self.assertEqual(result.exit_code, 0, result.stdout)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["report_lint"]["valid"])

    def test_schema_invalid_object_returns_one(self):
        with runner.isolated_filesystem():
            path = Path("report.json")
            path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
            result = runner.invoke(main_module.app, ["lint-report", str(path), "--json"])
            self.assertEqual(result.exit_code, 1, result.stdout)
            payload = json.loads(result.stdout)
            codes = {item["code"] for item in payload["report_lint"]["issues"]}
            self.assertIn("schema_validation_error", codes)


    def test_invalid_report_returns_one(self):
        with runner.isolated_filesystem():
            path = Path("report.json")
            path.write_text(
                json.dumps(
                    {
                        "findings": [{"severity": "CRITICAL", "title": "Secret exposed"}],
                        "summary": {"summary": "No critical issues.", "findings": []},
                    }
                ),
                encoding="utf-8",
            )
            result = runner.invoke(main_module.app, ["lint-report", str(path), "--json"])
            self.assertEqual(result.exit_code, 1, result.stdout)
            payload = json.loads(result.stdout)
            codes = {item["code"] for item in payload["report_lint"]["issues"]}
            self.assertIn("critical_missing_from_summary", codes)

    def test_write_sidecars_is_explicit(self):
        with runner.isolated_filesystem():
            path = Path("report.json")
            path.write_text(json.dumps({"schema_version": "1.0", "target": "localhost", "findings": [], "results": []}), encoding="utf-8")
            result = runner.invoke(main_module.app, ["lint-report", str(path), "--write-sidecars"])
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertTrue(Path("report-lint.json").exists())
            self.assertTrue(Path("report-lint.md").exists())

    def test_strict_mode_fails_on_likely_noise_warning(self):
        with runner.isolated_filesystem():
            path = Path("report.json")
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "target": "localhost",
                        "results": [],
                        "findings": [
                            {
                                "severity": "INFO",
                                "title": "Browser discovered URL",
                                "type": "browser_discovery",
                                "evidence": "HTTP 404 for http://localhost:3000/admin",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = runner.invoke(main_module.app, ["lint-report", str(path), "--strict"])
            self.assertEqual(result.exit_code, 1, result.stdout)
            self.assertIn("likely_noise_discovery", result.stdout)

    def test_malformed_json_returns_two(self):
        with runner.isolated_filesystem():
            path = Path("report.json")
            path.write_text("{not-json", encoding="utf-8")
            result = runner.invoke(main_module.app, ["lint-report", str(path)])
            self.assertEqual(result.exit_code, 2, result.stdout)
            self.assertIn("Unable to read report JSON", result.stdout)


if __name__ == "__main__":
    unittest.main()
