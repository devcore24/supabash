import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

import supabash.__main__ as main_module


runner = CliRunner()


class FakeReActOrchestrator:
    def run(self, target, output, **kwargs):
        cb = kwargs.get("progress_cb")
        if callable(cb):
            cb(event="plan_ready", tool="planner", message="Planned next steps: whatweb, nuclei", agg={"target": target, "mode": "normal", "react": {"actions": []}})
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("{}", encoding="utf-8")
        return {"target": target, "results": [], "findings": [], "saved_to": str(output)}


class TestReActCLI(unittest.TestCase):
    def test_react_writes_markdown_by_default(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = True
        main_module.config_manager.config.setdefault("core", {})["consent_accepted"] = True
        with runner.isolated_filesystem():
            with patch.object(main_module, "ReActOrchestrator", FakeReActOrchestrator):
                result = runner.invoke(main_module.app, ["react", "localhost", "--force", "--yes"])
            self.assertEqual(result.exit_code, 0, result.stdout)
            json_reports = list(Path("reports").glob("react-*.json"))
            md_reports = list(Path("reports").glob("react-*.md"))
            self.assertTrue(json_reports)
            self.assertTrue(md_reports)

    def test_react_status_file_written(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = True
        main_module.config_manager.config.setdefault("core", {})["consent_accepted"] = True
        with runner.isolated_filesystem():
            with patch.object(main_module, "ReActOrchestrator", FakeReActOrchestrator):
                result = runner.invoke(
                    main_module.app,
                    ["react", "localhost", "--force", "--yes", "--status-file", "status.json"],
                )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertTrue(Path("status.json").exists())

    def test_react_falls_back_when_output_not_writable(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = True
        main_module.config_manager.config.setdefault("core", {})["consent_accepted"] = True
        with runner.isolated_filesystem():
            Path("reports").mkdir(parents=True, exist_ok=True)
            locked = Path("reports/react-locked.json")
            locked.write_text("{}", encoding="utf-8")
            locked.chmod(0o444)
            try:
                with patch.object(main_module, "ReActOrchestrator", FakeReActOrchestrator):
                    result = runner.invoke(main_module.app, ["react", "localhost", "--force", "--yes", "--output", str(locked)])
                self.assertEqual(result.exit_code, 0, result.stdout)
                # The locked default should remain, but a timestamped sibling should exist.
                self.assertTrue(locked.exists())
                matches = list(Path("reports").glob("react-locked-*.json"))
                self.assertTrue(matches)
            finally:
                try:
                    locked.chmod(0o644)
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
