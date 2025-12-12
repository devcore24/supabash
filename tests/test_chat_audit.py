import unittest
from pathlib import Path

from supabash.chat import ChatSession


class DummyConfigManager:
    def __init__(self):
        self.config = {"core": {"consent_accepted": True, "allow_public_ips": True}}


class FakeAuditOrchestrator:
    def __init__(self):
        self.calls = []

    def run(self, target, output, **kwargs):
        self.calls.append((target, output, kwargs))
        return {
            "target": target,
            "results": [{"tool": "nmap", "success": True, "data": {"scan_data": {"hosts": []}}}],
            "findings": [{"severity": "HIGH", "title": "X", "evidence": "Y", "tool": "nuclei"}],
            "saved_to": str(output) if output is not None else None,
        }


class TestChatAudit(unittest.TestCase):
    def test_run_audit_sets_state(self):
        fake = FakeAuditOrchestrator()
        session = ChatSession(scanners={}, llm=None, config_manager=DummyConfigManager())
        session.audit_orchestrator_factory = lambda: fake

        report = session.run_audit("10.0.0.1", output=None, markdown=None)
        self.assertEqual(report["target"], "10.0.0.1")
        self.assertEqual(session.last_result_kind, "audit")
        self.assertIsNotNone(session.last_audit_report)
        self.assertIsNone(report.get("saved_to"))

        entry = session.get_audit_tool_result("nmap")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.get("tool"), "nmap")

    def test_run_audit_allows_optional_output(self):
        fake = FakeAuditOrchestrator()
        session = ChatSession(scanners={}, llm=None, config_manager=DummyConfigManager())
        session.audit_orchestrator_factory = lambda: fake
        out = Path("/tmp/chat_audit.json")
        report = session.run_audit("10.0.0.2", output=out)
        self.assertEqual(report.get("saved_to"), str(out))


if __name__ == "__main__":
    unittest.main()

