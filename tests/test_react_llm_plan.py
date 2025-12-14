import json
import unittest
from pathlib import Path

from supabash.react import ReActOrchestrator
from supabash import prompts


class FakeScanner:
    def __init__(self, name):
        self.name = name
        self.calls = 0

    def scan(self, *args, **kwargs):
        self.calls += 1
        if self.name == "nmap":
            return {
                "success": True,
                "scan_data": {
                    "hosts": [
                        {
                            "ports": [
                                {"port": 80, "protocol": "tcp", "service": "http", "state": "open"},
                            ]
                        }
                    ]
                },
            }
        return {"success": True, "scan_data": [], "findings": []}


class FakeLLMPlanner:
    def __init__(self):
        self.plan_calls = 0

    def chat_with_meta(self, messages, temperature=0.2):
        system = messages[0]["content"]
        if system == prompts.REACT_LLM_PLANNER_PROMPT:
            self.plan_calls += 1
            if self.plan_calls == 1:
                return (json.dumps({"next_steps": ["whatweb", "nuclei"], "notes": "web"}), {"usage": {"total_tokens": 1}})
            if self.plan_calls == 2:
                return (json.dumps({"next_steps": ["gobuster"], "notes": "content discovery"}), {"usage": {"total_tokens": 1}})
            return (json.dumps({"next_steps": ["stop"], "notes": "done"}), {"usage": {"total_tokens": 1}})
        # summary (analyzer)
        if system == prompts.ANALYZER_PROMPT:
            return (json.dumps({"summary": "ok", "findings": []}), {"usage": {"total_tokens": 1}})
        return (json.dumps({"summary": "ok", "findings": []}), {"usage": {"total_tokens": 1}})


class FailingLLMPlanner:
    def chat_with_meta(self, messages, temperature=0.2):
        system = messages[0]["content"]
        if system == prompts.REACT_LLM_PLANNER_PROMPT:
            raise RuntimeError("LLM down")
        return (json.dumps({"summary": "ok", "findings": []}), {"usage": {"total_tokens": 1}})


class TestReActLLMPlan(unittest.TestCase):
    def test_llm_plan_executes_steps_iteratively(self):
        scanners = {
            "nmap": FakeScanner("nmap"),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
        }
        llm = FakeLLMPlanner()
        orch = ReActOrchestrator(scanners=scanners, llm_client=llm, planner=None)
        out = Path("/tmp/react_llm_plan.json")
        report = orch.run("example.com", out, llm_plan=True, max_actions=5)
        self.assertTrue(out.exists())
        self.assertGreaterEqual(llm.plan_calls, 2)
        actions = report.get("react", {}).get("actions", [])
        self.assertIn("whatweb", actions)
        self.assertIn("nuclei", actions)
        self.assertIn("gobuster", actions)
        out.unlink(missing_ok=True)

    def test_llm_plan_failure_sets_error_and_writes_report(self):
        scanners = {
            "nmap": FakeScanner("nmap"),
            "whatweb": FakeScanner("whatweb"),
        }
        orch = ReActOrchestrator(scanners=scanners, llm_client=FailingLLMPlanner(), planner=None)
        out = Path("/tmp/react_llm_plan_fail.json")
        report = orch.run("example.com", out, llm_plan=True, max_actions=3)
        self.assertTrue(out.exists())
        self.assertTrue(report.get("error"))
        self.assertTrue(report.get("failed"))
        out.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

