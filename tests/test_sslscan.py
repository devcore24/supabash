import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.sslscan import SslscanScanner
from supabash.runner import CommandResult


SAMPLE_SSLSCAN = """
Version: 2.1.6-static
OpenSSL 1.1.1

SSLv2      disabled
SSLv3      enabled
TLSv1.0    enabled
TLSv1.1    disabled
TLSv1.2    enabled
TLSv1.3    enabled
"""


class TestSslscanScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = SslscanScanner(runner=self.mock_runner)

    def test_scan_command(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_SSLSCAN, stderr="", success=True
        )
        res = self.scanner.scan("example.com", port=443)
        self.assertTrue(res["success"])
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "sslscan")
        self.assertIn("--no-colour", cmd)
        self.assertIn("example.com:443", cmd)

    def test_parses_weak_protocols(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_SSLSCAN, stderr="", success=True
        )
        res = self.scanner.scan("example.com", port=443)
        weak = res["scan_data"]["weak_protocols_enabled"]
        self.assertIn("SSLV3", [w.upper() for w in weak])
        self.assertIn("TLSV1.0", [w.upper() for w in weak])

    def test_failure_uses_stdout_when_stderr_empty(self):
        self.mock_runner.run.return_value = CommandResult(
            command="sslscan", return_code=2, stdout="bad flag", stderr="", success=False
        )
        res = self.scanner.scan("example.com", port=443)
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "bad flag")


if __name__ == "__main__":
    unittest.main()

