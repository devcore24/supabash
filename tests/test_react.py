import json
import unittest
from pathlib import Path

from supabash.react import ReActOrchestrator
from tests.test_artifacts import artifact_path, cleanup_artifact


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


class FakePlannerHydra:
    def suggest(self, state):
        return {"next_steps": ["hydra:ssh"], "notes": "ssh"}


class FakeHydra:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {
            "success": True,
            "raw_output": "[22][ssh] host: 127.0.0.1   login: root   password: toor",
            "found_credentials": [{"host": "127.0.0.1", "login": "root", "password": "toor", "service": "ssh", "port": "22"}],
            "command": "hydra ...",
        }


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
        out = artifact_path("react_report.json")
        report = orch.run("example.com", out, max_actions=5)
        self.assertTrue(out.exists())
        self.assertIn("react", report)
        self.assertIn("schema_version", report)
        self.assertIn("schema_validation", report)
        self.assertEqual(report["react"]["actions"][:3], ["whatweb", "nuclei", "gobuster"])
        tools = [r.get("tool") for r in report.get("results", [])]
        self.assertIn("nmap", tools)
        self.assertIn("whatweb", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("gobuster", tools)
        cleanup_artifact(out)

    def test_react_runs_hydra_when_opted_in(self):
        class NmapWithSsh(FakeScanner):
            def scan(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return {
                    "success": True,
                    "scan_data": {
                        "hosts": [
                            {
                                "ports": [
                                    {"port": 22, "protocol": "tcp", "service": "ssh", "product": "", "version": "", "state": "open"},
                                ]
                            }
                        ]
                    },
                }

        scanners = {
            "nmap": NmapWithSsh("nmap"),
            "hydra": FakeHydra(),
            "sqlmap": FakeScanner("sqlmap"),
            "trivy": FakeScanner("trivy"),
            "supabase_rls": FakeScanner("supabase_rls"),
        }
        orch = ReActOrchestrator(scanners=scanners, llm_client=FakeLLM(), planner=FakePlannerHydra())
        out = artifact_path("react_hydra_test.json")
        report = orch.run(
            "127.0.0.1",
            out,
            max_actions=3,
            run_hydra=True,
            hydra_usernames="users.txt",
            hydra_passwords="pass.txt",
            hydra_services="ssh",
        )
        self.assertTrue(out.exists())
        tools = [r.get("tool") for r in report.get("results", [])]
        self.assertIn("hydra", tools)
        hydra_entry = next((r for r in report.get("results", []) if r.get("tool") == "hydra"), None)
        self.assertIsNotNone(hydra_entry)
        self.assertTrue(hydra_entry.get("success"))
        cleanup_artifact(out)

if __name__ == "__main__":
    unittest.main()
