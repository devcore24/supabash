import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import patch

from supabash.ai_audit import AIAuditOrchestrator
from supabash.audit import AuditOrchestrator


class DummyConfig:
    config = {
        "core": {"report_exports": {"html": False, "pdf": False}},
        "llm": {"enabled": False},
        "tools": {},
    }


class DummyLLM:
    config = DummyConfig()

class EnabledConfig:
    config = {
        "core": {"report_exports": {"html": False, "pdf": False}},
        "llm": {"enabled": True, "max_input_chars": 12000},
        "tools": {},
    }


class CancelingLLM:
    config = EnabledConfig()

    def __init__(self, cancel_event):
        self.cancel_event = cancel_event
        self.chat_called = False

    def tool_call(self, *args, **kwargs):
        self.cancel_event.set()
        return [], {}

    def chat(self, *args, **kwargs):
        self.chat_called = True
        raise AssertionError("summary LLM call must not run after cancellation")


class SummaryOnlyLLM:
    config = EnabledConfig()

    def tool_call(self, *args, **kwargs):
        raise AssertionError("planner must not run without eligible tools")

    def chat(self, *args, **kwargs):
        return json.dumps({"summary": "No agentic tools were eligible.", "findings": []})


class TestAuditCancellation(unittest.TestCase):
    def _run_canceled(self, orchestrator_class, output: Path):
        cancel = Event()
        cancel.set()
        orchestrator = orchestrator_class(scanners={"nmap": object()}, llm_client=DummyLLM())
        kwargs = {"cancel_event": cancel, "use_llm": False}
        if orchestrator_class is AIAuditOrchestrator:
            kwargs["llm_plan"] = False
        return orchestrator.run("localhost", output, **kwargs)

    def test_baseline_early_cancellation_persists_complete_partial_report(self):
        with TemporaryDirectory() as td:
            output = Path(td) / "canceled.json"
            report = self._run_canceled(AuditOrchestrator, output)
            self.assertTrue(report["canceled"])
            self.assertEqual(report["saved_to"], str(output))
            self.assertTrue(output.exists())
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(persisted["saved_to"], str(output))
            self.assertTrue(persisted["schema_validation"]["valid"])
            self.assertIn("summary", persisted)
            self.assertIn("finding_metrics", persisted)
            self.assertIn("report_lint", persisted)
            self.assertIn("evidence_pack", persisted)
            self.assertTrue(output.with_name("canceled-lint.json").exists())

    def test_ai_early_cancellation_uses_same_partial_report_contract(self):
        with TemporaryDirectory() as td:
            output = Path(td) / "ai-canceled.json"
            report = self._run_canceled(AIAuditOrchestrator, output)
            self.assertTrue(report["canceled"])
            self.assertEqual(report["report_kind"], "ai_audit")
            self.assertTrue(output.exists())
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(persisted["schema_validation"]["valid"])
            self.assertIn("report_lint", persisted)
            self.assertIn("replay_trace", persisted)

    def test_ai_mid_agentic_cancellation_finalizes_without_summary_llm_call(self):
        cancel = Event()
        llm = CancelingLLM(cancel)
        baseline = {
            "schema_version": "1.0",
            "report_kind": "audit",
            "target": "localhost",
            "scan_host": "localhost",
            "mode": "normal",
            "started_at": 1.0,
            "finished_at": 2.0,
            "results": [],
            "findings": [],
            "summary": {
                "summary": "Baseline complete.",
                "findings": [],
            },
            "web_targets": ["http://localhost"],
            "service_targets": [],
            "llm": {
                "enabled": False,
                "reason": "Disabled for baseline",
                "calls": [],
            },
        }
        with TemporaryDirectory() as td:
            output = Path(td) / "ai-mid-canceled.json"
            with patch.object(AuditOrchestrator, "run", return_value=baseline):
                orchestrator = AIAuditOrchestrator(
                    scanners={"httpx": object()},
                    llm_client=llm,
                )
                report = orchestrator.run(
                    "localhost",
                    output,
                    cancel_event=cancel,
                    use_llm=True,
                    llm_plan=True,
                    max_actions=1,
                )

            self.assertTrue(report["canceled"])
            self.assertTrue(report["ai_audit"]["canceled"])
            self.assertEqual(report["ai_audit"]["phase"], "agentic")
            self.assertFalse(llm.chat_called)
            self.assertTrue(output.exists())


    def test_ai_no_eligible_tools_still_finalizes(self):
        baseline = {
            "schema_version": "1.0",
            "report_kind": "audit",
            "target": "localhost",
            "scan_host": "localhost",
            "mode": "normal",
            "started_at": 1.0,
            "finished_at": 2.0,
            "results": [],
            "findings": [],
            "summary": {"summary": "Baseline complete.", "findings": []},
            "web_targets": [],
            "service_targets": [],
            "llm": {"enabled": False, "calls": []},
        }
        with TemporaryDirectory() as td:
            output = Path(td) / "ai-no-tools.json"
            with patch.object(AuditOrchestrator, "run", return_value=baseline):
                orchestrator = AIAuditOrchestrator(
                    scanners={"nmap": object()},
                    llm_client=SummaryOnlyLLM(),
                )
                report = orchestrator.run(
                    "localhost",
                    output,
                    use_llm=True,
                    llm_plan=True,
                    max_actions=1,
                )

            self.assertTrue(output.exists())
            self.assertTrue(report["ai_audit"]["agentic_skipped"])
            self.assertIn("No eligible tools", report["ai_audit"]["planner"]["warning"])
            self.assertIn("baseline_action_ledger", report)


if __name__ == "__main__":
    unittest.main()
