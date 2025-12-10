import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.trivy import TrivyScanner
from supabash.runner import CommandResult

SAMPLE_JSON = """
{
  "Results": [
    {
      "Target": "alpine:3.18 (alpine 3.18.4)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2025-0001",
          "PkgName": "openssl",
          "InstalledVersion": "3.1.2-r0",
          "FixedVersion": "3.1.3-r0",
          "Severity": "HIGH",
          "Title": "openssl vulnerability"
        }
      ]
    }
  ]
}
"""


class TestTrivyScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = TrivyScanner(runner=self.mock_runner)

    def test_parse_json(self):
        findings = self.scanner._parse_json(SAMPLE_JSON)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "CVE-2025-0001")
        self.assertEqual(findings[0]["pkg"], "openssl")

    def test_scan_command_construction(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_JSON, stderr="", success=True
        )
        self.scanner.scan("alpine:3.18", severity="CRITICAL")
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "trivy")
        self.assertIn("image", cmd)
        self.assertIn("--format", cmd)
        self.assertIn("json", cmd)
        self.assertIn("--severity", cmd)
        self.assertIn("CRITICAL", cmd)
        self.assertIn("alpine:3.18", cmd)

    def test_scan_failure(self):
        self.mock_runner.run.return_value = CommandResult(
            command="trivy", return_code=1, stdout="", stderr="error", success=False
        )
        result = self.scanner.scan("bad")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "error")


if __name__ == '__main__':
    unittest.main()
