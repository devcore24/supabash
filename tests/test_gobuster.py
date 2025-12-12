import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.gobuster import GobusterScanner
from supabash.runner import CommandResult

SAMPLE_GOBUSTER_OUTPUT = """
/admin (Status: 301)
/login (Status: 200)
"""

class TestGobusterScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = GobusterScanner(runner=self.mock_runner)

    def test_parse_output(self):
        findings = self.scanner._parse_output(SAMPLE_GOBUSTER_OUTPUT)
        self.assertEqual(len(findings), 2)
        self.assertIn("/admin (Status: 301)", findings)

    def test_scan_command(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="", stderr="", success=True
        )

        self.scanner.scan("http://example.com")

        self.mock_runner.run.assert_called_once()
        args, _ = self.mock_runner.run.call_args
        command = args[0]
        
        self.assertEqual(command[0], "gobuster")
        self.assertEqual(command[1], "dir")
        self.assertIn("-u", command)
        self.assertIn("http://example.com", command)
        self.assertIn("-w", command)
        # should choose a default wordlist (system or bundled)
        w_index = command.index("-w")
        self.assertTrue(command[w_index + 1])
        self.assertIn("-t", command)

    def test_scan_threads_override(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="", stderr="", success=True
        )
        self.scanner.scan("http://example.com", threads=25)
        args, _ = self.mock_runner.run.call_args
        command = args[0]
        self.assertIn("-t", command)
        t_index = command.index("-t")
        self.assertEqual(command[t_index + 1], "25")

if __name__ == '__main__':
    unittest.main()
