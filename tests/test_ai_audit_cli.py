import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

import supabash.__main__ as main_module


runner = CliRunner()


class FakeAIAuditOrchestrator:
    def run(self, target, output, **kwargs):
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("{}", encoding="utf-8")
        return {
            "target": target,
            "results": [],
            "findings": [],
            "report_kind": "ai_audit",
            "ai_audit": {"phase": "baseline+agentic", "actions": []},
            "saved_to": str(out_path),
        }


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
                json_reports = list(Path("reports").glob("ai-audit-*.json"))
                md_reports = list(Path("reports").glob("ai-audit-*.md"))
                self.assertTrue(json_reports)
                self.assertTrue(md_reports)
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
                json_reports = list(Path("reports").glob("ai-audit-*.json"))
                self.assertTrue(json_reports)
        finally:
            core["report_exports"] = exports_prev

    def test_audit_react_flag_is_alias_for_agentic(self):
        core = main_module.config_manager.config.setdefault("core", {})
        exports_prev = dict(core.get("report_exports", {}) or {})
        core["report_exports"] = {"html": False, "pdf": False}
        try:
            with runner.isolated_filesystem():
                with patch.object(main_module, "AIAuditOrchestrator", FakeAIAuditOrchestrator):
                    result = runner.invoke(main_module.app, ["audit", "localhost", "--react", "--force", "--yes"])
                self.assertEqual(result.exit_code, 0, result.stdout)
                json_reports = list(Path("reports").glob("ai-audit-*.json"))
                self.assertTrue(json_reports)
        finally:
            core["report_exports"] = exports_prev


if __name__ == "__main__":
    unittest.main()
