import unittest
import json
from pathlib import Path

from supabash.audit import AuditOrchestrator


class FakeScanner:
    def __init__(self, name):
        self.name = name

    def scan(self, *args, **kwargs):
        if self.name == "nmap":
            return {
                "success": True,
                "scan_data": {
                    "hosts": [
                        {
                            "ports": [
                                {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.0", "state": "open"}
                            ]
                        }
                    ]
                },
            }
        if self.name == "nuclei":
            return {"success": True, "findings": [{"severity": "high", "name": "Test Vuln", "matched_at": "http://t/"}]}
        return {"success": True, "scan_data": []}


class FakeLLM:
    def chat_with_meta(self, messages, temperature=0.2):
        system = messages[0]["content"]
        if "Output JSON" in system and "security analyst" in system:
            return (
                json.dumps({"summary": "ok", "findings": [{"severity": "HIGH", "title": "Test Vuln", "evidence": "x", "recommendation": ""}]}),
                {"usage": {"total_tokens": 10}, "cost_usd": 0.001, "provider": "openai", "model": "gpt-4"},
            )
        return (
            json.dumps({"summary": "Do X", "steps": ["Step 1"], "code_sample": "print('fix')"}),
            {"usage": {"total_tokens": 20}, "cost_usd": 0.002, "provider": "openai", "model": "gpt-4"},
        )


class TestRemediation(unittest.TestCase):
    def test_audit_remediation_enriches_findings(self):
        scanners = {
            "nmap": FakeScanner("nmap"),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
            "trivy": FakeScanner("trivy"),
            "supabase_rls": FakeScanner("supabase_rls"),
        }
        orchestrator = AuditOrchestrator(scanners=scanners, llm_client=FakeLLM())
        out = Path("/tmp/remediation_report.json")
        report = orchestrator.run("example.com", out, remediate=True, max_remediations=1, min_remediation_severity="HIGH")
        self.assertTrue(out.exists())
        self.assertIn("findings", report)
        # Ensure at least one finding was enriched
        enriched = [f for f in report["findings"] if f.get("remediation")]
        self.assertTrue(enriched)
        self.assertIn("code_sample", enriched[0])
        # Ensure llm call metadata is tracked
        self.assertIn("llm", report)
        self.assertIsInstance(report["llm"].get("calls"), list)
        out.unlink()


if __name__ == "__main__":
    unittest.main()

