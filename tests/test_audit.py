import unittest
import json
from pathlib import Path
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.audit import AuditOrchestrator


class FakeScanner:
    def __init__(self, name):
        self.name = name
        self.called = False

    def scan(self, *args, **kwargs):
        self.called = True
        if self.name == "nmap":
            return {
                "success": True,
                "scan_data": {
                    "hosts": [
                        {"ports": [{"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.0", "state": "open"}]}
                    ]
                }
            }
        return {"success": True, "data": self.name}


class FakeFailScanner:
    def __init__(self, name):
        self.name = name

    def scan(self, *args, **kwargs):
        return {"success": False, "error": "fail"}


class TestAuditOrchestrator(unittest.TestCase):
    def test_runs_scanners_and_writes_file(self, tmp_path=None):
        scanners = {
            "nmap": FakeScanner("nmap"),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
            "trivy": FakeScanner("trivy"),
        }
        class FakeLLM:
            def chat(self, messages, temperature=0.2):
                return '{"summary":"ok","findings":[]}'

        orchestrator = AuditOrchestrator(scanners=scanners, llm_client=FakeLLM())
        output = Path("/tmp/audit_test.json")
        report = orchestrator.run("example.com", output, container_image="alpine:latest")
        self.assertTrue(output.exists())
        data = json.loads(output.read_text())
        self.assertEqual(data["target"], "example.com")
        self.assertEqual(data["container_image"], "alpine:latest")
        # ensure all tools ran
        tool_names = [r["tool"] for r in data["results"]]
        self.assertIn("trivy", tool_names)
        self.assertIn("findings", data)
        self.assertGreaterEqual(len(data["findings"]), 1)
        output.unlink()

    def test_handles_failure(self):
        scanners = {
            "nmap": FakeFailScanner("nmap"),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
            "trivy": FakeScanner("trivy"),
        }
        class FakeLLM:
            def chat(self, messages, temperature=0.2):
                return '{"summary":"ok","findings":[]}'

        orchestrator = AuditOrchestrator(scanners=scanners, llm_client=FakeLLM())
        output = Path("/tmp/audit_fail.json")
        report = orchestrator.run("example.com", output)
        failures = [r for r in report["results"] if not r["success"]]
        self.assertTrue(failures)
        output.unlink()


if __name__ == "__main__":
    unittest.main()
