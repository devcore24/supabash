import unittest
from pathlib import Path

from supabash.audit import AuditOrchestrator
from tests.test_artifacts import artifact_path, cleanup_artifact


class BombLLM:
    def chat(self, *args, **kwargs):
        raise AssertionError("LLM should not be called in --no-llm mode")

    def chat_with_meta(self, *args, **kwargs):
        raise AssertionError("LLM should not be called in --no-llm mode")


class FakeScanner:
    def __init__(self, name, result):
        self.name = name
        self.result = result
        self.calls = []

    def scan(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result


class TestNoLLMMode(unittest.TestCase):
    def test_audit_no_llm_skips_summary_and_remediation(self):
        scanners = {
            "nmap": FakeScanner("nmap", {"success": True, "scan_data": {"hosts": []}, "command": "nmap t"}),
            "whatweb": FakeScanner("whatweb", {"success": True, "scan_data": [], "command": "whatweb t"}),
            "nuclei": FakeScanner("nuclei", {"success": True, "findings": [], "command": "nuclei t"}),
            "gobuster": FakeScanner("gobuster", {"success": True, "findings": [], "command": "gobuster t"}),
            "sqlmap": FakeScanner("sqlmap", {"success": True, "findings": [], "command": "sqlmap t"}),
            "nikto": FakeScanner("nikto", {"success": True, "scan_data": {}, "command": "nikto t"}),
            "sslscan": FakeScanner("sslscan", {"success": True, "scan_data": {}, "command": "sslscan t"}),
            "dnsenum": FakeScanner("dnsenum", {"success": True, "scan_data": {}, "command": "dnsenum t"}),
            "enum4linux-ng": FakeScanner("enum4linux-ng", {"success": True, "raw_output": "", "command": "enum4linux-ng t"}),
            "trivy": FakeScanner("trivy", {"success": True, "findings": [], "command": "trivy t"}),
            "supabase_audit": type("Noop", (), {"scan": lambda self, urls, **kw: {"success": True, "data": {}, "command": "supabase_audit"}})(),
        }
        orch = AuditOrchestrator(scanners=scanners, llm_client=BombLLM())
        out = artifact_path("no_llm_audit.json")
        report = orch.run("t", out, remediate=True, use_llm=False)
        self.assertTrue(out.exists())
        self.assertNotIn("summary", report)
        self.assertEqual(report.get("llm", {}).get("enabled"), False)
        cleanup_artifact(out)

if __name__ == "__main__":
    unittest.main()
