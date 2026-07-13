import json
import unittest
from pathlib import Path

from typer.testing import CliRunner

import supabash.__main__ as main_module


runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "benchmarks"


class TestBenchmarkReportCLI(unittest.TestCase):
    def test_positive_fixture_passes_and_writes_machine_result(self):
        with runner.isolated_filesystem():
            output = Path("score.json")
            result = runner.invoke(
                main_module.app,
                [
                    "benchmark-report",
                    str(FIXTURES / "soc2-positive-report.json"),
                    str(FIXTURES / "soc2-positive-expectations.json"),
                    "--json",
                    "--output",
                    str(output),
                ],
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertTrue(json.loads(result.stdout)["benchmark"]["passed"])
            self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["benchmark"]["passed"])

    def test_protected_fixture_passes(self):
        result = runner.invoke(
            main_module.app,
            [
                "benchmark-report",
                str(FIXTURES / "pci-protected-report.json"),
                str(FIXTURES / "pci-protected-expectations.json"),
            ],
        )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("PASSED", result.stdout)

    def test_malformed_expectations_return_usage_error(self):
        with runner.isolated_filesystem():
            expectations = Path("expectations.json")
            expectations.write_text(json.dumps({"required_risk_classes": "not-a-list"}), encoding="utf-8")
            result = runner.invoke(
                main_module.app,
                [
                    "benchmark-report",
                    str(FIXTURES / "soc2-positive-report.json"),
                    str(expectations),
                ],
            )
            self.assertEqual(result.exit_code, 2, result.stdout)
            self.assertIn("required_risk_classes", result.stdout)
            self.assertIn("non-empty", result.stdout)


if __name__ == "__main__":
    unittest.main()
