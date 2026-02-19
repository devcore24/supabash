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
            session=None,
            profile=None,
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
            session=None,
            profile=None,
            command_override=None,
        )

        self.assertIsNotNone(cmd)
        self.assertIn("--headed", cmd)
        self.assertEqual(cmd[:4], ["/usr/bin/browser-use", "--json", "--headed", "run"])

    def test_build_command_includes_session_and_profile_when_configured(self):
        scanner = BrowserUseScanner()
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        cmd = scanner._build_command(
            target="http://example.test",
            task="Open site",
            max_steps=5,
            headless=True,
            model=None,
            session="audit-session",
            profile="team-profile",
            command_override=None,
        )

        self.assertIsNotNone(cmd)
        self.assertIn("--session", cmd)
        self.assertIn("audit-session", cmd)
        self.assertIn("--profile", cmd)
        self.assertIn("team-profile", cmd)

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

    def test_scan_marks_incomplete_when_done_false_and_no_evidence(self):
        cli_json = (
            '{"id":"x2","success":true,"data":{"success":true,'
            '"task":"Inspect target","steps":0,"done":false,"result":null}}'
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

        out = scanner.scan("http://example.test", task="Inspect target", max_steps=1)

        self.assertFalse(out.get("success"))
        self.assertIn("did not complete", str(out.get("error") or ""))
        obs = out.get("observation") if isinstance(out, dict) else {}
        self.assertEqual(obs.get("done"), False)
        self.assertEqual(obs.get("steps"), 0)

    def test_scan_success_returns_observation_when_done_and_steps_positive(self):
        cli_json = (
            '{"id":"x3","success":true,"data":{"success":true,'
            '"task":"Inspect target","steps":3,"done":true,'
            '"result":"Found potential misconfig at http://example.test/admin"}}'
        )
        result = CommandResult(
            command="browser-use --json run task --max-steps 3",
            return_code=0,
            stdout=cli_json,
            stderr="",
            success=True,
        )
        runner = _FakeRunner(result)
        scanner = BrowserUseScanner(runner=runner)
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        out = scanner.scan("http://example.test", task="Inspect target", max_steps=3)

        self.assertTrue(out.get("success"))
        observation = out.get("observation") if isinstance(out, dict) else {}
        self.assertEqual(observation.get("done"), True)
        self.assertEqual(observation.get("steps"), 3)
        self.assertGreaterEqual(int(observation.get("evidence_score") or 0), 1)


if __name__ == "__main__":
    unittest.main()
