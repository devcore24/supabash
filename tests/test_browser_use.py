import unittest
from typing import List

from supabash.runner import CommandResult
from supabash.tools.browser_use import BrowserUseScanner


class _FakeRunner:
    def __init__(self, result: CommandResult):
        self._result = result
        self.last_command = None

    def run(self, command, **kwargs):
        self.last_command = list(command or [])
        return self._result


class _SequenceRunner:
    def __init__(self, results: List[CommandResult]):
        self._results = list(results or [])
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append(list(command or []))
        if self._results:
            return self._results.pop(0)
        return CommandResult(
            command=" ".join(str(x) for x in (command or [])),
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )


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
        self.assertEqual(int(obs.get("findings_count") or 0), 0)
        self.assertEqual(int(obs.get("evidence_score") or 0), 0)

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

    def test_scan_uses_deterministic_probe_when_run_is_incomplete(self):
        run_incomplete = CommandResult(
            command="browser-use --json run task --max-steps 2",
            return_code=0,
            stdout=(
                '{"id":"x4","success":true,"data":{"success":true,'
                '"task":"Inspect target","steps":0,"done":false,"result":null}}'
            ),
            stderr="",
            success=True,
        )
        open_ok = CommandResult(
            command="browser-use --json open http://example.test",
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )
        state_ok = CommandResult(
            command="browser-use --json state",
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )
        title_root = CommandResult(
            command="browser-use --json get title",
            return_code=0,
            stdout='{"success":true,"data":{"success":true,"title":"WebGoat"}}',
            stderr="",
            success=True,
        )
        html_root = CommandResult(
            command="browser-use --json get html",
            return_code=0,
            stdout=(
                '{"success":true,"data":{"success":true,'
                '"html":"<html><body><form action=\\"/login\\"></form>'
                'javax.servlet.ServletException</body></html>"}}'
            ),
            stderr="",
            success=True,
        )
        open_login = CommandResult(
            command="browser-use --json open http://example.test/login",
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )
        title_login = CommandResult(
            command="browser-use --json get title",
            return_code=0,
            stdout='{"success":true,"data":{"success":true,"title":"Login"}}',
            stderr="",
            success=True,
        )

        runner = _SequenceRunner([run_incomplete, open_ok, state_ok, title_root, html_root, open_login, title_login])
        scanner = BrowserUseScanner(runner=runner)
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        out = scanner.scan("http://example.test", task="Inspect target", max_steps=2, deterministic_max_paths=1)

        self.assertTrue(out.get("success"))
        self.assertEqual(out.get("completed"), False)
        obs = out.get("observation") if isinstance(out, dict) else {}
        self.assertEqual(obs.get("fallback_mode"), "deterministic_probe")
        self.assertGreaterEqual(int(obs.get("fallback_findings_count") or 0), 1)
        findings = out.get("findings") if isinstance(out.get("findings"), list) else []
        self.assertTrue(any("Form attack surface" in str(f.get("title") or "") for f in findings if isinstance(f, dict)))

    def test_scan_retries_without_session_after_socket_timeout(self):
        run_timeout = CommandResult(
            command="browser-use --json --session audit-session run task --max-steps 2",
            return_code=1,
            stdout="",
            stderr="TimeoutError: timed out",
            success=False,
        )
        retry_ok = CommandResult(
            command="browser-use --json run task --max-steps 2",
            return_code=0,
            stdout=(
                '{"id":"x5","success":true,"data":{"success":true,'
                '"task":"Inspect target","steps":2,"done":true,'
                '"result":"Visited http://example.test/admin"}}'
            ),
            stderr="",
            success=True,
        )
        runner = _SequenceRunner([run_timeout, retry_ok])
        scanner = BrowserUseScanner(runner=runner)
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        out = scanner.scan(
            "http://example.test",
            task="Inspect target",
            max_steps=2,
            session="audit-session",
        )

        self.assertTrue(out.get("success"))
        self.assertEqual(len(runner.calls), 2)
        first_call = runner.calls[0] if runner.calls else []
        second_call = runner.calls[1] if len(runner.calls) > 1 else []
        self.assertIn("--session", first_call)
        self.assertIn("audit-session", first_call)
        self.assertNotIn("--session", second_call)

    def test_scan_uses_deterministic_fallback_when_run_fails(self):
        run_timeout = CommandResult(
            command="browser-use --json --session audit-session run task --max-steps 2",
            return_code=1,
            stdout="",
            stderr="TimeoutError: timed out",
            success=False,
        )
        retry_timeout = CommandResult(
            command="browser-use --json run task --max-steps 2",
            return_code=1,
            stdout="",
            stderr="TimeoutError: timed out",
            success=False,
        )
        open_ok = CommandResult(
            command="browser-use --json open http://example.test",
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )
        state_ok = CommandResult(
            command="browser-use --json state",
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )
        title_root = CommandResult(
            command="browser-use --json get title",
            return_code=0,
            stdout='{"success":true,"data":{"success":true,"title":"WebGoat"}}',
            stderr="",
            success=True,
        )
        html_root = CommandResult(
            command="browser-use --json get html",
            return_code=0,
            stdout=(
                '{"success":true,"data":{"success":true,'
                '"html":"<html><body><form action=\\"/login\\"></form>'
                'javax.servlet.ServletException</body></html>"}}'
            ),
            stderr="",
            success=True,
        )
        open_login = CommandResult(
            command="browser-use --json open http://example.test/login",
            return_code=0,
            stdout='{"success":true,"data":{"success":true}}',
            stderr="",
            success=True,
        )
        title_login = CommandResult(
            command="browser-use --json get title",
            return_code=0,
            stdout='{"success":true,"data":{"success":true,"title":"Login"}}',
            stderr="",
            success=True,
        )

        runner = _SequenceRunner(
            [run_timeout, retry_timeout, open_ok, state_ok, title_root, html_root, open_login, title_login]
        )
        scanner = BrowserUseScanner(runner=runner)
        scanner._resolve_cli_binary = lambda: "/usr/bin/browser-use"

        out = scanner.scan(
            "http://example.test",
            task="Inspect target",
            max_steps=2,
            session="audit-session",
            deterministic_max_paths=1,
        )

        self.assertTrue(out.get("success"))
        self.assertEqual(out.get("completed"), False)
        obs = out.get("observation") if isinstance(out, dict) else {}
        self.assertEqual(obs.get("fallback_mode"), "deterministic_probe_on_run_failure")
        self.assertGreaterEqual(int(obs.get("fallback_findings_count") or 0), 1)


if __name__ == "__main__":
    unittest.main()
