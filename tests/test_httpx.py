import unittest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.httpx import HttpxScanner
from supabash.runner import CommandResult


class TestHttpxScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = HttpxScanner(runner=self.mock_runner)
        self.resolver = patch(
            "supabash.tools.httpx.resolve_tool_executable",
            return_value="/usr/local/bin/httpx",
        )
        self.resolver.start()
        self.addCleanup(self.resolver.stop)

    def test_parses_json_lines_and_alive_urls(self):
        stdout = "\n".join(
            [
                '{"url":"http://example.com","status_code":200,"title":"OK"}',
                '{"url":"https://example.com","status_code":301,"title":"Moved"}',
                "not json",
                "",
            ]
        )
        self.mock_runner.run.return_value = CommandResult(command="httpx ...", return_code=0, stdout=stdout, stderr="", success=True)
        out = self.scanner.scan(["http://example.com", "https://example.com"])
        self.assertTrue(out["success"])
        self.assertIn("alive", out)
        self.assertIn("http://example.com", out["alive"])
        self.assertIn("https://example.com", out["alive"])

    def test_command_contains_expected_flags(self):
        self.mock_runner.run.return_value = CommandResult(command="", return_code=0, stdout="{}", stderr="", success=True)
        self.scanner.scan("http://example.com", threads=10, follow_redirects=False)
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(os.path.basename(cmd[0]), "httpx")
        self.assertIn("-json", cmd)
        self.assertIn("-silent", cmd)
        self.assertIn("-l", cmd)
        self.assertIn("-threads", cmd)
        # follow_redirects=False should not include -follow-redirects
        self.assertNotIn("-follow-redirects", cmd)

    def test_redirect_following_is_disabled_by_default(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="{}", stderr="", success=True
        )

        self.scanner.scan("http://example.com")

        command = self.mock_runner.run.call_args.args[0]
        self.assertNotIn("-follow-redirects", command)

    def test_scan_uses_shared_registry_resolution(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="{}", stderr="", success=True
        )

        with patch(
            "supabash.tools.httpx.resolve_tool_executable",
            return_value="/usr/local/bin/httpx",
        ):
            self.scanner.scan("http://example.com")

        command = self.mock_runner.run.call_args.args[0]
        self.assertEqual(command[0], "/usr/local/bin/httpx")

    def test_scan_fails_closed_when_no_verified_projectdiscovery_binary_exists(self):
        with patch(
            "supabash.tools.httpx.resolve_tool_executable",
            return_value=None,
        ):
            result = self.scanner.scan("http://example.com")

        self.assertFalse(result["success"])
        self.assertIn("refusing to execute an unverified", result["error"])
        self.mock_runner.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
