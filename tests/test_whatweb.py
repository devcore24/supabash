import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.whatweb import WhatWebScanner
from supabash.runner import CommandResult

SAMPLE_JSONL = """
{"target":"http://example.com","plugins":{"HTTPServer":["nginx"],"X-Powered-By":["PHP/8.2"]},"http_status":200,"banner":"nginx"}
{"target":"http://example.com/favicon.ico","plugins":{"Content-Type":["image/x-icon"]},"http_status":200}
"""


class TestWhatWebScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = WhatWebScanner(runner=self.mock_runner)

    def test_parse_json_lines(self):
        parsed = self.scanner._parse_json_lines(SAMPLE_JSONL)
        self.assertEqual(len(parsed), 2)
        first = parsed[0]
        self.assertEqual(first["target"], "http://example.com")
        self.assertIn("HTTPServer", first["plugins"])
        self.assertEqual(first["status"], 200)

    def test_scan_command_construction(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_JSONL, stderr="", success=True
        )
        self.scanner.scan("http://example.com")
        self.mock_runner.run.assert_called_once()
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "whatweb")
        self.assertIn("--log-json", cmd)
        self.assertIn("-", cmd)

    def test_scan_failure(self):
        self.mock_runner.run.return_value = CommandResult(
            command="whatweb", return_code=1, stdout="", stderr="error", success=False
        )
        result = self.scanner.scan("bad")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "error")


if __name__ == '__main__':
    unittest.main()
