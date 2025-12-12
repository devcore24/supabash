import json
import unittest
from pathlib import Path

from supabash.react import ReActOrchestrator


class FakeScanner:
    def __init__(self, name):
        self.name = name
        self.calls = []

    def scan(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.name == "nmap":
            return {
                "success": True,
                "scan_data": {
                    "hosts": [
                        {
                            "ports": [
                                {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.0", "state": "open"},
                            ]
                        }
                    ]
                },
            }
        if self.name == "whatweb":
            return {"success": True, "scan_data": [{"plugins": {"nginx": {}, "php": {}}}]}
        if self.name == "nuclei":
            return {"success": True, "findings": [{"severity": "high", "name": "Test Vuln", "matched_at": "http://t/"}]}
        if self.name == "gobuster":
            return {"success": True, "findings": ["/admin (Status: 301)"]}
        return {"success": True}


class FakeLLM:
    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "ok", "findings": []}),
            {"usage": {"total_tokens": 10}, "cost_usd": 0.001, "provider": "openai", "model": "gpt-4"},
        )


class FakePlanner:
    def suggest(self, state):
        return {"next_steps": ["whatweb", "nuclei", "gobuster"], "notes": "web"}


class TestReAct(unittest.TestCase):
    def test_react_runs_planned_web_tools(self):
        scanners = {
            "nmap": FakeScanner("nmap"),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
            "trivy": FakeScanner("trivy"),
            "supabase_rls": FakeScanner("supabase_rls"),
        }
        orch = ReActOrchestrator(scanners=scanners, llm_client=FakeLLM(), planner=FakePlanner())
        out = Path("/tmp/react_report.json")
        report = orch.run("example.com", out, max_actions=5)
        self.assertTrue(out.exists())
        self.assertIn("react", report)
        self.assertEqual(report["react"]["actions"][:3], ["whatweb", "nuclei", "gobuster"])
        tools = [r.get("tool") for r in report.get("results", [])]
        self.assertIn("nmap", tools)
        self.assertIn("whatweb", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("gobuster", tools)
        out.unlink()


if __name__ == "__main__":
    unittest.main()

