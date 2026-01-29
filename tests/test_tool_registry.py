import json
import unittest
from pathlib import Path

from supabash.audit import AuditOrchestrator
from tests.test_artifacts import artifact_path, cleanup_artifact


class DummyConfigManager:
    def __init__(self, tools_cfg):
        self.config = {
            "llm": {"max_input_chars": 12000},
            "tools": tools_cfg,
        }


class FakeLLM:
    def __init__(self, cfg):
        self.config = cfg

    def chat(self, messages, temperature=0.2):
        return json.dumps({"summary": "ok", "findings": []})


class SpyScanner:
    def __init__(self, name, result=None):
        self.name = name
        self.calls = 0
        self.result = result if result is not None else {"success": True, "scan_data": {"hosts": []}}

    def scan(self, *args, **kwargs):
        self.calls += 1
        return self.result


class TestToolRegistry(unittest.TestCase):
    def test_disabled_tool_is_skipped(self):
        nmap = SpyScanner(
            "nmap",
            result={
                "success": True,
                "scan_data": {
                    "hosts": [
                        {"ports": [{"port": 80, "protocol": "tcp", "service": "http", "state": "open"}]},
                    ]
                },
            },
        )
        whatweb = SpyScanner("whatweb", result={"success": True, "scan_data": []})
        nuclei = SpyScanner("nuclei", result={"success": True, "findings": []})
        gobuster = SpyScanner("gobuster", result={"success": True, "findings": []})

        cfg = DummyConfigManager(tools_cfg={"whatweb": {"enabled": False}})
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
                "supabase_audit": SpyScanner("supabase_audit"),
            },
            llm_client=FakeLLM(cfg),
        )

        out = artifact_path("tool_registry_test.json")
        report = orch.run("example.com", out)
        self.assertTrue(out.exists())
        cleanup_artifact(out)

        self.assertEqual(nmap.calls, 1)
        self.assertEqual(whatweb.calls, 0)

        entry = next((e for e in report.get("results", []) if e.get("tool") == "whatweb"), None)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.get("skipped"))


if __name__ == "__main__":
    unittest.main()
