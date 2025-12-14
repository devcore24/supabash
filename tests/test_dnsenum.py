import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.dnsenum import DnsenumScanner
from supabash.runner import CommandResult


SAMPLE_DNSENUM = """
dnsenum.pl VERSION:1.2.6
www.example.com. 93.184.216.34
mail.example.com 93.184.216.34
"""


class TestDnsenumScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = DnsenumScanner(runner=self.mock_runner)

    def test_scan_command(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_DNSENUM, stderr="", success=True
        )
        res = self.scanner.scan("example.com")
        self.assertTrue(res["success"])
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "dnsenum")
        self.assertIn("example.com", cmd)

    def test_parses_hosts(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_DNSENUM, stderr="", success=True
        )
        res = self.scanner.scan("example.com")
        hosts = res["scan_data"]["hosts"]
        self.assertEqual(len(hosts), 2)
        self.assertIn("93.184.216.34", res["scan_data"]["ips"])

    def test_failure_uses_stdout_when_stderr_empty(self):
        self.mock_runner.run.return_value = CommandResult(
            command="dnsenum", return_code=2, stdout="error", stderr="", success=False
        )
        res = self.scanner.scan("example.com")
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "error")


if __name__ == "__main__":
    unittest.main()

