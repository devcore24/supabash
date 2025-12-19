import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.subfinder import SubfinderScanner
from supabash.runner import CommandResult


class TestSubfinderScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = SubfinderScanner(runner=self.mock_runner)

    def test_parses_jsonl_hosts(self):
        stdout = "\n".join(
            [
                '{"host":"a.example.com","source":"crtsh"}',
                '{"host":"b.example.com","source":"dnsdumpster"}',
                "",
            ]
        )
        self.mock_runner.run.return_value = CommandResult(command="subfinder ...", return_code=0, stdout=stdout, stderr="", success=True)
        out = self.scanner.scan("example.com")
        self.assertTrue(out["success"])
        self.assertEqual(out["hosts"], ["a.example.com", "b.example.com"])

    def test_command_contains_expected_flags(self):
        self.mock_runner.run.return_value = CommandResult(command="", return_code=0, stdout="", stderr="", success=True)
        self.scanner.scan("example.com")
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "subfinder")
        self.assertIn("-d", cmd)
        self.assertIn("example.com", cmd)
        self.assertIn("-silent", cmd)
        self.assertIn("-json", cmd)


if __name__ == "__main__":
    unittest.main()

