import unittest

from supabash.audit import AuditOrchestrator


class TestLLMSummaryContext(unittest.TestCase):
    def test_context_prioritizes_high_severity_and_includes_tool_status(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        agg = {
            "target": "localhost",
            "scan_host": "localhost",
            "mode": "normal",
            "open_ports": [8080, 9090],
            "web_targets": ["http://localhost:8080", "http://localhost:9090"],
            "results": [
                {"tool": "nmap", "success": True, "command": "nmap localhost -sV"},
                {"tool": "httpx", "success": False, "error": "bad flag", "command": "httpx -silent ..."},
            ],
        }
        findings = [
            {"severity": "INFO", "title": "Noise", "evidence": "x", "tool": "nuclei"},
            {"severity": "HIGH", "title": "Important", "evidence": "y", "tool": "nuclei"},
            {"severity": "INFO", "title": "Noise", "evidence": "x", "tool": "nuclei"},  # dup
        ]

        ctx = orch._build_llm_summary_context(agg, findings)
        self.assertEqual(ctx["findings_overview"]["HIGH"], 1)
        self.assertEqual(ctx["findings"][0]["severity"], "HIGH")
        self.assertTrue(any(t.get("tool") == "httpx" and t.get("status") == "failed" for t in ctx["tools"]))


if __name__ == "__main__":
    unittest.main()

