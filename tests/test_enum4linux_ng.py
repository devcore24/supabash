import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.enum4linux_ng import Enum4linuxNgScanner
from supabash.runner import CommandResult


class TestEnum4linuxNgScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = Enum4linuxNgScanner(runner=self.mock_runner)

    def test_scan_command(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="ok", stderr="", success=True
        )
        res = self.scanner.scan("10.0.0.5")
        self.assertTrue(res["success"])
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "enum4linux-ng")
        self.assertIn("-A", cmd)
        self.assertIn("10.0.0.5", cmd)

    def test_failure_uses_stdout_when_stderr_empty(self):
        self.mock_runner.run.return_value = CommandResult(
            command="enum4linux-ng", return_code=2, stdout="fail", stderr="", success=False
        )
        res = self.scanner.scan("10.0.0.5")
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "fail")


if __name__ == "__main__":
    unittest.main()

