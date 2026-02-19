import unittest

from supabash.runner import CommandResult
from supabash.tools.browser_use import BrowserUseScanner


class _FakeRunner:
    def __init__(self, result: CommandResult):
        self._result = result
        self.last_command = None

    def run(self, command, **kwargs):
        self.last_command = list(command or [])
        return self._result


class BrowserUseScannerTests(unittest.TestCase):
    def test_build_command_headless_true_uses_json_without_headless_flag(self):
        scanner = BrowserUseScanner()
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        cmd = scanner._build_command(
            target="http://example.test",
            task="Open site",
            max_steps=5,
            headless=True,
            model=None,
            command_override=None,
        )

        self.assertIsNotNone(cmd)
        self.assertIn("--json", cmd)
        self.assertNotIn("--headless", cmd)
        self.assertNotIn("--headed", cmd)
        self.assertEqual(cmd[:3], ["/usr/bin/browser-use", "--json", "run"])

    def test_build_command_headed_mode_uses_headed_flag(self):
        scanner = BrowserUseScanner()
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        cmd = scanner._build_command(
            target="http://example.test",
            task="Open site",
            max_steps=5,
            headless=False,
            model=None,
            command_override=None,
        )

        self.assertIsNotNone(cmd)
        self.assertIn("--headed", cmd)
        self.assertEqual(cmd[:4], ["/usr/bin/browser-use", "--json", "--headed", "run"])

    def test_scan_marks_cli_level_failure_when_return_code_is_zero(self):
        cli_json = (
            '{"id":"x1","success":true,"data":{"success":false,'
            '"error":"API key required"}}'
        )
        result = CommandResult(
            command="browser-use --json run task --max-steps 1",
            return_code=0,
            stdout=cli_json,
            stderr="",
            success=True,
        )
        runner = _FakeRunner(result)
        scanner = BrowserUseScanner(runner=runner)
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        out = scanner.scan("http://example.test", task="Open site", max_steps=1)

        self.assertFalse(out.get("success"))
        self.assertIn("API key required", str(out.get("error") or ""))
        self.assertEqual(
            runner.last_command[:3],
            ["/usr/bin/browser-use", "--json", "run"],
        )


if __name__ == "__main__":
    unittest.main()

