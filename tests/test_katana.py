import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.katana import KatanaScanner
from supabash.runner import CommandResult


class TestKatanaScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = KatanaScanner(runner=self.mock_runner)

    def test_parses_jsonl_endpoints(self):
        stdout = "\n".join(
            [
                '{"request":{"endpoint":"http://example.com/"}}',
                '{"request":{"endpoint":"http://example.com/login"}}',
                "",
            ]
        )
        self.mock_runner.run.return_value = CommandResult(command="katana ...", return_code=0, stdout=stdout, stderr="", success=True)
        out = self.scanner.crawl("http://example.com")
        self.assertTrue(out["success"])
        self.assertIn("urls", out)
        self.assertEqual(out["urls"], ["http://example.com/", "http://example.com/login"])

    def test_command_contains_expected_flags(self):
        self.mock_runner.run.return_value = CommandResult(command="", return_code=0, stdout="", stderr="", success=True)
        self.scanner.crawl("http://example.com", depth=2, concurrency=15)
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "katana")
        self.assertIn("-u", cmd)
        self.assertIn("http://example.com", cmd)
        self.assertIn("-depth", cmd)
        self.assertIn("2", cmd)
        self.assertIn("-concurrency", cmd)
        self.assertIn("15", cmd)
        self.assertIn("-jsonl", cmd)
        self.assertIn("-silent", cmd)


if __name__ == "__main__":
    unittest.main()

