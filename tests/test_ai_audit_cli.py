import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

import supabash.__main__ as main_module


runner = CliRunner()


class FakeAIAuditOrchestrator:
    last_kwargs = None

    def run(self, target, output, **kwargs):
        FakeAIAuditOrchestrator.last_kwargs = dict(kwargs)
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("{}", encoding="utf-8")
        return {
            "target": target,
            "results": [],
            "findings": [],
            "report_kind": "ai_audit",
            "ai_audit": {"phase": "baseline+agentic", "actions": []},
            "replay_trace": {
                "file": "ai-audit-test-replay.json",
                "markdown_file": "ai-audit-test-replay.md",
                "step_count": 1,
                "version": 1,
            },
            "saved_to": str(out_path),
        }


class FakeCodexAIAuditOrchestrator(FakeAIAuditOrchestrator):
    pass


class TestAIAuditCLI(unittest.TestCase):
    def test_ai_audit_command_writes_reports(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        try:
            with runner.isolated_filesystem():
                with patch.object(main_module, "AIAuditOrchestrator", FakeAIAuditOrchestrator):
                    result = runner.invoke(main_module.app, ["ai-audit", "localhost", "--force", "--yes"])
                self.assertEqual(result.exit_code, 0, result.stdout)
                json_reports = list(Path("reports").glob("ai-audit-*/*.json"))
                md_reports = list(Path("reports").glob("ai-audit-*/*.md"))
                self.assertTrue(json_reports)
                self.assertTrue(md_reports)
                if md_reports:
                    md_text = md_reports[0].read_text(encoding="utf-8")
                    self.assertIn("## Reproducibility Trace", md_text)
        finally:
            core["report_exports"] = exports_prev

    def test_audit_agentic_uses_ai_audit_basename(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        try:
            with runner.isolated_filesystem():
                with patch.object(main_module, "AIAuditOrchestrator", FakeAIAuditOrchestrator):
                    result = runner.invoke(main_module.app, ["audit", "localhost", "--agentic", "--force", "--yes"])
                self.assertEqual(result.exit_code, 0, result.stdout)
                self.assertIn("initializing AI audit protocol", result.stdout)
                json_reports = list(Path("reports").glob("ai-audit-*/*.json"))
                self.assertTrue(json_reports)
        finally:
            core["report_exports"] = exports_prev

    def test_ai_audit_compliance_uses_prefixed_basename(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        try:
            with runner.isolated_filesystem():
                with patch.object(main_module, "AIAuditOrchestrator", FakeAIAuditOrchestrator):
                    result = runner.invoke(
                        main_module.app,
                        ["ai-audit", "localhost", "--compliance", "pci", "--force", "--yes"],
                    )
                self.assertEqual(result.exit_code, 0, result.stdout)
                json_reports = list(Path("reports").glob("ai-audit-pci-*/*.json"))
                md_reports = list(Path("reports").glob("ai-audit-pci-*/*.md"))
                self.assertTrue(json_reports)
                self.assertTrue(md_reports)
        finally:
            core["report_exports"] = exports_prev

    def test_ai_audit_no_browser_use_flag_is_forwarded(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        FakeAIAuditOrchestrator.last_kwargs = None
        try:
            with runner.isolated_filesystem():
                with patch.object(main_module, "AIAuditOrchestrator", FakeAIAuditOrchestrator):
                    result = runner.invoke(
                        main_module.app,
                        ["ai-audit", "localhost", "--no-browser-use", "--force", "--yes"],
                    )
                self.assertEqual(result.exit_code, 0, result.stdout)
                self.assertIsInstance(FakeAIAuditOrchestrator.last_kwargs, dict)
                self.assertEqual(FakeAIAuditOrchestrator.last_kwargs.get("run_browser_use"), False)
        finally:
            core["report_exports"] = exports_prev

    def test_ai_audit_codex_backend_uses_codex_controller(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        FakeCodexAIAuditOrchestrator.last_kwargs = None
        try:
            with runner.isolated_filesystem(), patch(
                "supabash.codex_audit.CodexAIAuditOrchestrator",
                FakeCodexAIAuditOrchestrator,
            ), patch.object(
                main_module,
                "AIAuditOrchestrator",
                side_effect=AssertionError("legacy planner must not be constructed"),
            ):
                result = runner.invoke(
                    main_module.app,
                    ["ai-audit", "localhost", "--agent-backend", "codex", "--force", "--yes"],
                )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertTrue(list(Path("reports").glob("ai-audit-*/*.json")))
        finally:
            core["report_exports"] = exports_prev

    def test_audit_codex_backend_implies_agentic_naming(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        try:
            with runner.isolated_filesystem(), patch(
                "supabash.codex_audit.CodexAIAuditOrchestrator",
                FakeCodexAIAuditOrchestrator,
            ):
                result = runner.invoke(
                    main_module.app,
                    ["audit", "localhost", "--agent-backend", "codex", "--force", "--yes"],
                )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("initializing AI audit protocol", result.stdout)
            self.assertTrue(list(Path("reports").glob("ai-audit-*/*.json")))
        finally:
            core["report_exports"] = exports_prev

    def test_codex_backend_rejects_offline_llm_flags(self):
        result = runner.invoke(
            main_module.app,
            ["ai-audit", "localhost", "--agent-backend", "codex", "--no-llm", "--force", "--yes"],
        )
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("--no-llm cannot be combined", result.stdout)

    def test_codex_backend_reports_preflight_failure_cleanly(self):
        from supabash.codex_audit import CodexBackendUnavailable

        class UnavailableCodex:
            def run(self, *args, **kwargs):
                raise CodexBackendUnavailable("ChatGPT login required")

        with patch("supabash.codex_audit.CodexAIAuditOrchestrator", UnavailableCodex):
            result = runner.invoke(
                main_module.app,
                ["ai-audit", "localhost", "--agent-backend", "codex", "--force", "--yes"],
            )
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Codex backend is not ready", result.stdout)
        self.assertIn("ChatGPT login required", result.stdout)

    def test_chat_rejects_codex_backend_instead_of_silently_using_legacy(self):
        class FakeChatSession:
            def __init__(self, *args, **kwargs):
                self.run_audit_called = False

            def load_state(self, path):
                return {"success": False}

            def job_status(self):
                return None

            def add_message(self, *args, **kwargs):
                return None

            def run_audit(self, *args, **kwargs):
                self.run_audit_called = True
                raise AssertionError("chat must not silently run the legacy backend")

        for command in (
            "/ai-audit localhost --agent-backend codex",
            "/ai-audit localhost --agent-backend=codex",
        ):
            with self.subTest(command=command):
                fake_session = FakeChatSession()
                with patch.object(main_module, "ChatSession", return_value=fake_session), patch.object(
                    main_module.typer,
                    "prompt",
                    side_effect=[command, "exit"],
                ):
                    result = runner.invoke(main_module.app, ["chat"])

                self.assertEqual(result.exit_code, 0, result.stdout)
                self.assertIn(
                    "Codex agent backend is currently available from the terminal CLI only",
                    result.stdout,
                )
                self.assertFalse(fake_session.run_audit_called)

    def test_audit_markdown_write_failure_exits_nonzero(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        try:
            with runner.isolated_filesystem(), patch.object(
                main_module, "AIAuditOrchestrator", FakeAIAuditOrchestrator
            ), patch("supabash.report.write_markdown", side_effect=OSError("disk full")):
                result = runner.invoke(
                    main_module.app,
                    ["ai-audit", "localhost", "--force", "--yes"],
                )
            self.assertNotEqual(result.exit_code, 0, result.stdout)
            self.assertIn("Failed to write Markdown report", result.stdout)
        finally:
            core["report_exports"] = exports_prev


if __name__ == "__main__":
    unittest.main()
