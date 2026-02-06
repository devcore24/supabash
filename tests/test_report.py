import unittest
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.report import generate_markdown, write_markdown
from tests.test_artifacts import artifact_path, cleanup_artifact


class TestReport(unittest.TestCase):
    def test_generate_markdown_basic(self):
        report = {
            "target": "example.com",
            "results": [
                {"tool": "nmap", "success": True, "command": "nmap example.com -oX - -sV"},
                {"tool": "nuclei", "success": False, "error": "fail", "command": "nuclei -u http://example.com -jsonl"},
            ],
            "summary": {
                "summary": "One issue found.",
                "findings": [
                    {"severity": "high", "title": "SQLi", "evidence": "param id injectable", "recommendation": "Use prepared statements"},
                    {"severity": "low", "title": "Missing header", "evidence": "X-Frame-Options", "recommendation": "Set header"},
                ]
            },
            "started_at": 1.0,
            "finished_at": 2.0,
            "findings": [{"severity": "HIGH", "title": "SQLi", "tool": "sqlmap"}],
        }
        md = generate_markdown(report)
        self.assertIn("Supabash Audit", md)
        self.assertIn("example.com", md)
        self.assertIn("SQLi", md)
        self.assertIn("nmap", md)
        self.assertIn("fail", md)
        self.assertIn("Table of Contents", md)
        self.assertIn("Findings Overview", md)
        self.assertIn("Summary (LLM)", md)
        self.assertIn("Detailed (Tools)", md)
        self.assertIn("| Tool | Status | Command |", md)
        self.assertIn("Commands Executed", md)
        self.assertIn("nmap example.com", md)

    def test_generate_markdown_includes_evidence_pack_section(self):
        report = {
            "target": "localhost",
            "results": [],
            "evidence_pack": {
                "dir": "evidence/ai-audit-pci-20260206-000000",
                "manifest": "evidence/ai-audit-pci-20260206-000000/manifest.json",
                "artifact_count": 3,
                "runtime": {
                    "python_version": "3.12.3",
                    "platform": "Linux-x86_64",
                    "llm_providers": ["openai"],
                    "llm_models": ["gpt-5.1"],
                    "tool_versions": {"nmap": "Nmap version 7.94"},
                },
            },
        }
        md = generate_markdown(report)
        self.assertIn("## Evidence Pack", md)
        self.assertIn("directory:", md)
        self.assertIn("manifest:", md)
        self.assertIn("artifact_count: 3", md)
        self.assertIn("### Runtime Metadata", md)
        self.assertIn("### Tool Versions", md)

    def test_risk_normalization_details_include_rule_hints(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Exposure risk identified.",
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "title": "Database and cache services exposed on network ports",
                        "evidence": "PostgreSQL and Redis detected on open ports.",
                    }
                ],
            },
            "findings": [
                {"severity": "INFO", "title": "Open port 5432/tcp", "tool": "nmap", "evidence": "postgresql PostgreSQL DB 9.6.0 or later"},
                {"severity": "INFO", "title": "Open port 6379/tcp", "tool": "nmap", "evidence": "redis Redis key-value store 6.2.11"},
            ],
            "results": [],
        }
        md = generate_markdown(report)
        self.assertIn("### Risk Normalization", md)
        self.assertIn("#### Normalization Details", md)
        self.assertIn("rule:data_store_exposure_aggregation", md)

    def test_compliance_coverage_matrix_includes_skip_and_failure_reasons(self):
        report = {
            "target": "localhost",
            "compliance_profile": "compliance_pci",
            "compliance_framework": "PCI-DSS 4.0",
            "results": [
                {"tool": "nmap", "success": True, "command": "nmap localhost -oX - -sV --script ssl-enum-ciphers -p-"},
                {
                    "tool": "sslscan",
                    "success": False,
                    "skipped": True,
                    "reason": "No TLS candidate ports detected from discovery",
                },
                {
                    "tool": "nuclei",
                    "success": False,
                    "error": "connection reset by peer while requesting templates",
                },
            ],
        }
        md = generate_markdown(report)
        self.assertIn("## Compliance Coverage Matrix", md)
        self.assertIn("Transport Security Review", md)
        self.assertIn("skipped: sslscan (No TLS candidate ports detected from discovery)", md)
        self.assertIn("Vulnerability Discovery & Exposure Checks", md)
        self.assertIn("failed: nuclei (connection reset by peer while requesting templates)", md)

    def test_write_markdown(self):
        report = {"target": "t", "results": []}
        path = artifact_path("test_md_report.md")
        written = write_markdown(report, path)
        self.assertTrue(Path(written).exists())
        cleanup_artifact(Path(written))


if __name__ == "__main__":
    unittest.main()
