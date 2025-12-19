import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.ffuf import FfufScanner
from supabash.runner import CommandResult


class TestFfufScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = FfufScanner(runner=self.mock_runner)

    def test_parses_json_and_builds_findings(self):
        stdout = (
            '{"results":[{"url":"http://example.com/admin","status":200,"length":123},'
            '{"url":"http://example.com/robots.txt","status":200,"length":26}]}'
        )
        self.mock_runner.run.return_value = CommandResult(
            command="ffuf ...",
            return_code=0,
            stdout=stdout,
            stderr="",
            success=True,
        )

        out = self.scanner.scan("http://example.com")
        self.assertTrue(out["success"])
        self.assertIn("findings", out)
        self.assertEqual(len(out["findings"]), 2)
        self.assertIn("http://example.com/admin", out["findings"][0])
        self.assertIn("Status: 200", out["findings"][0])

    def test_command_contains_expected_flags(self):
        self.mock_runner.run.return_value = CommandResult(
            command="",
            return_code=0,
            stdout='{"results":[]}',
            stderr="",
            success=True,
        )
        self.scanner.scan("http://example.com", threads=10)
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "ffuf")
        self.assertIn("-u", cmd)
        self.assertIn("-w", cmd)
        self.assertIn("-of", cmd)
        self.assertIn("json", cmd)
        self.assertIn("-o", cmd)
        self.assertIn("-", cmd)
        self.assertIn("-ac", cmd)

    def test_rejects_targets_without_scheme(self):
        out = self.scanner.scan("example.com")
        self.assertFalse(out["success"])
        self.assertIn("http://", out["error"])


if __name__ == "__main__":
    unittest.main()

