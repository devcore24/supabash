import unittest
from unittest.mock import patch

from typer.testing import CliRunner
import supabash.__main__ as main_module
from tests.test_artifacts import artifact_path, cleanup_artifact


runner = CliRunner()


class FakeAuditOrchestrator:
    def run(self, target, output, **kwargs):
        return {"saved_to": str(output)}


class TestAuditCLI(unittest.TestCase):
    def test_audit_blocks_public_ip_by_default(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = False
        out = artifact_path("audit_cli_blocked.json")
        result = runner.invoke(
            main_module.app,
            ["audit", "8.8.8.8", "--force", "--yes", "--output", str(out)],
        )
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Refusing to scan public IP targets", result.stdout)
        cleanup_artifact(out)
        cleanup_artifact(out.with_suffix(".md"))
        cleanup_artifact(out.with_suffix(".html"))
        cleanup_artifact(out.with_suffix(".pdf"))

    def test_audit_allows_public_ip_with_flag(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = False
        out = artifact_path("audit_cli_allowed.json")
        with patch.object(main_module, "AuditOrchestrator", FakeAuditOrchestrator):
            result = runner.invoke(
                main_module.app,
                ["audit", "8.8.8.8", "--force", "--yes", "--allow-public", "--output", str(out)],
            )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("initializing full audit protocol", result.stdout)
        cleanup_artifact(out)
        cleanup_artifact(out.with_suffix(".md"))
        cleanup_artifact(out.with_suffix(".html"))
        cleanup_artifact(out.with_suffix(".pdf"))


if __name__ == "__main__":
    unittest.main()
