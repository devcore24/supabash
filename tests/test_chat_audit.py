import unittest
from pathlib import Path
from unittest.mock import patch

from supabash.chat import ChatSession
from tests.test_artifacts import artifact_path, cleanup_artifact


class DummyConfigManager:
    def __init__(self):
        self.config = {"core": {"consent_accepted": True, "allow_public_ips": True}}


class FakeAuditOrchestrator:
    def __init__(self):
        self.calls = []

    def run(self, target, output, **kwargs):
        self.calls.append((target, output, kwargs))
        progress_cb = kwargs.get("progress_cb")
        if callable(progress_cb):
            progress_cb(event="tool_start", tool="nmap", message="Running nmap", agg={"target": target})
            progress_cb(event="tool_end", tool="nmap", message="Finished nmap", agg={"target": target})
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

    def test_audit_bg_job_records_events(self):
        fake = FakeAuditOrchestrator()
        session = ChatSession(scanners={}, llm=None, config_manager=DummyConfigManager())
        session.audit_orchestrator_factory = lambda: fake
        job = session.start_audit_job("10.0.0.3")
        # wait until done
        for _ in range(50):
            done = session.finalize_job_if_done()
            if done:
                break
            import time
            time.sleep(0.01)
        self.assertIsNotNone(done)
        status = done["status"]
        self.assertTrue(status.events)

    def test_run_audit_allows_optional_output(self):
        fake = FakeAuditOrchestrator()
        session = ChatSession(scanners={}, llm=None, config_manager=DummyConfigManager())
        session.audit_orchestrator_factory = lambda: fake
        out = artifact_path("chat_audit.json")
        report = session.run_audit("10.0.0.2", output=out)
        self.assertEqual(report.get("saved_to"), str(out))
        cleanup_artifact(out)

    def test_run_audit_agentic_uses_ai_audit_orchestrator(self):
        fake = FakeAuditOrchestrator()
        session = ChatSession(scanners={}, llm=None, config_manager=DummyConfigManager())

        with patch("supabash.chat.AIAuditOrchestrator", return_value=fake):
            report = session.run_audit(
                "10.0.0.4",
                agentic=True,
                llm_plan=False,
                max_actions=2,
                no_llm=True,
                run_browser_use=False,
                compliance_profile="soc2",
            )

        self.assertEqual(report.get("target"), "10.0.0.4")
        self.assertTrue(fake.calls)
        kwargs = fake.calls[0][2]
        self.assertEqual(kwargs.get("llm_plan"), False)
        self.assertEqual(kwargs.get("max_actions"), 2)
        self.assertEqual(kwargs.get("use_llm"), False)
        self.assertEqual(kwargs.get("run_browser_use"), False)
        self.assertEqual(kwargs.get("compliance_profile"), "soc2")


if __name__ == "__main__":
    unittest.main()
