import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.audit import AuditOrchestrator
from supabash.react import ReActOrchestrator


class DummyConfigManager:
    def __init__(self, cfg):
        self.config = cfg


class FakeLLM:
    def __init__(self, cfg):
        self.config = cfg

    def chat(self, messages, temperature=0.2):
        return '{"summary":"ok","findings":[]}'

    def chat_with_meta(self, messages, temperature=0.2):
        return ('{"summary":"ok","findings":[]}', {"usage": {"total_tokens": 1}})


class SpyScanner:
    def __init__(self, name, result=None):
        self.name = name
        self.calls = []
        self.result = result if result is not None else {"success": True, "scan_data": {"hosts": []}}

    def scan(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result


class TestAggressiveCaps(unittest.TestCase):
    def test_audit_aggressive_caps_clamp_nuclei_and_gobuster(self):
        cfg = DummyConfigManager(
            {
                "core": {
                    "aggressive_caps": {
                        "max_nuclei_rate": 7,
                        "default_nuclei_rate": 5,
                        "max_gobuster_threads": 9,
                        "max_parallel_workers": 2,
                    }
                },
                "llm": {"max_input_chars": 12000},
                "tools": {"nmap": {"enabled": True}, "whatweb": {"enabled": True}, "nuclei": {"enabled": True}, "gobuster": {"enabled": True}},
            }
        )

        nmap = SpyScanner("nmap", result={"success": True, "scan_data": {"hosts": [{"ports": [{"port": 80, "state": "open", "protocol": "tcp", "service": "http"}]}]}})
        whatweb = SpyScanner("whatweb", result={"success": True, "scan_data": []})
        nuclei = SpyScanner("nuclei", result={"success": True, "findings": []})
        gobuster = SpyScanner("gobuster", result={"success": True, "findings": []})

        orch = AuditOrchestrator(
            scanners={
                "nmap": nmap,
                "whatweb": whatweb,
                "nuclei": nuclei,
                "gobuster": gobuster,
                "sqlmap": SpyScanner("sqlmap"),
                "nikto": SpyScanner("nikto"),
                "sslscan": SpyScanner("sslscan"),
                "dnsenum": SpyScanner("dnsenum"),
                "enum4linux-ng": SpyScanner("enum4linux-ng"),
                "trivy": SpyScanner("trivy"),
                "supabase_rls": type("Noop", (), {"check": lambda self, url, **kw: {"success": True, "data": {}, "command": "rls"}})(),
            },
            llm_client=FakeLLM(cfg),
        )

        report = orch.run(
            "http://localhost",
            output=None,
            mode="aggressive",
            nuclei_rate_limit=999,
            gobuster_threads=999,
            parallel_web=True,
            max_workers=999,
        )

        # nuclei called with capped rate limit
        self.assertTrue(nuclei.calls, "nuclei was not called")
        _, nuclei_kwargs = nuclei.calls[0]
        self.assertEqual(nuclei_kwargs.get("rate_limit"), 7)

        # gobuster called with capped threads
        self.assertTrue(gobuster.calls, "gobuster was not called")
        _, gobuster_kwargs = gobuster.calls[0]
        self.assertEqual(gobuster_kwargs.get("threads"), 9)

        # report includes caps metadata
        caps = report.get("safety", {}).get("aggressive_caps", {})
        self.assertTrue(caps.get("enabled"))
        self.assertIn("applied", caps)

    def test_react_aggressive_sets_default_nuclei_rate_when_zero(self):
        cfg = DummyConfigManager({"core": {"aggressive_caps": {"default_nuclei_rate": 3, "max_nuclei_rate": 4}}, "llm": {"max_input_chars": 12000}, "tools": {}})
        nmap = SpyScanner("nmap", result={"success": True, "scan_data": {"hosts": [{"ports": [{"port": 80, "state": "open", "protocol": "tcp", "service": "http"}]}]}})
        nuclei = SpyScanner("nuclei", result={"success": True, "findings": []})
        whatweb = SpyScanner("whatweb", result={"success": True, "scan_data": []})
        gobuster = SpyScanner("gobuster", result={"success": True, "findings": []})

        class Planner:
            def suggest(self, state):
                return {"next_steps": ["whatweb", "nuclei"], "notes": "web"}

        orch = ReActOrchestrator(
            scanners={"nmap": nmap, "whatweb": whatweb, "nuclei": nuclei, "gobuster": gobuster},
            llm_client=FakeLLM(cfg),
            planner=Planner(),
        )

        report = orch.run("http://localhost", output=None, mode="aggressive", nuclei_rate_limit=0, max_actions=3)
        self.assertTrue(nuclei.calls, "nuclei was not called")
        _, nuclei_kwargs = nuclei.calls[0]
        self.assertEqual(nuclei_kwargs.get("rate_limit"), 3)
        caps = report.get("safety", {}).get("aggressive_caps", {})
        self.assertTrue(caps.get("enabled"))


if __name__ == "__main__":
    unittest.main()

