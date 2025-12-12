import unittest
from unittest.mock import patch

from typer.testing import CliRunner
import supabash.__main__ as main_module


runner = CliRunner()


class FakeAuditOrchestrator:
    def run(self, target, output, **kwargs):
        return {"saved_to": str(output)}


class TestAuditCLI(unittest.TestCase):
    def test_audit_blocks_public_ip_by_default(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = False
        result = runner.invoke(
            main_module.app,
            ["audit", "8.8.8.8", "--force", "--yes", "--output", "report.json"],
        )
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Refusing to scan public IP targets", result.stdout)

    def test_audit_allows_public_ip_with_flag(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = False
        with patch.object(main_module, "AuditOrchestrator", FakeAuditOrchestrator):
            result = runner.invoke(
                main_module.app,
                ["audit", "8.8.8.8", "--force", "--yes", "--allow-public", "--output", "report.json"],
            )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("initializing full audit protocol", result.stdout)


if __name__ == "__main__":
    unittest.main()

