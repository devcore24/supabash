import unittest
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.report import COMPLIANCE_COVERAGE_ROWS, generate_markdown, write_markdown
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

    def test_summary_findings_are_correlated_and_evidence_merged(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Exposure found.",
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Prometheus configuration API exposed without authentication",
                        "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                        "recommendation": "Restrict access to /api/v1/*.",
                    },
                    {
                        "severity": "HIGH",
                        "title": "Prometheus configuration API exposed without authentication",
                        "evidence": "readiness_probe confirmed config endpoint exposure.",
                        "recommendation": "Restrict access to /api/v1/*.",
                    },
                ],
            },
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus configuration API exposed without authentication",
                    "tool": "nuclei",
                    "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                },
                {
                    "severity": "HIGH",
                    "title": "Prometheus configuration API exposed without authentication",
                    "tool": "readiness_probe",
                    "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                },
            ],
            "results": [],
        }
        md = generate_markdown(report)
        # In the summary section, heading should appear once; evidence should be merged/corroborated.
        summary_start = md.find("\n### Findings")
        methodology_start = md.find("\n## Methodology")
        self.assertGreaterEqual(summary_start, 0)
        self.assertGreater(methodology_start, summary_start)
        summary_block = md[summary_start:methodology_start]
        self.assertEqual(summary_block.count("**HIGH** Prometheus configuration API exposed without authentication"), 1)
        self.assertIn("  - Evidence:", summary_block)
        self.assertIn("    - readiness_probe confirmed config endpoint exposure.", summary_block)
        self.assertIn("    - nuclei: http://localhost:9090/api/v1/status/config (HTTP 200)", summary_block)

    def test_summary_findings_include_evidence_artifact_references(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Exposure found.",
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Prometheus configuration API exposed without authentication",
                        "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                        "recommendation": "Restrict access to /api/v1/*.",
                    }
                ],
            },
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus configuration API exposed without authentication",
                    "tool": "nuclei",
                    "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                }
            ],
            "evidence_pack": {
                "manifest": "evidence/ai-audit-soc2-20260208-000000/manifest.json",
                "artifacts": [
                    {
                        "tool": "nuclei",
                        "status": "success",
                        "path": "evidence/ai-audit-soc2-20260208-000000/results/005-nuclei.json",
                    }
                ],
            },
            "results": [],
        }
        md = generate_markdown(report)
        summary_start = md.find("\n### Findings")
        methodology_start = md.find("\n## Methodology")
        self.assertGreaterEqual(summary_start, 0)
        self.assertGreater(methodology_start, summary_start)
        summary_block = md[summary_start:methodology_start]
        self.assertIn("Evidence Artifacts: `evidence/ai-audit-soc2-20260208-000000/results/005-nuclei.json`", summary_block)
        self.assertIn("Manifest Reference: `evidence/ai-audit-soc2-20260208-000000/manifest.json`", summary_block)

    def test_summary_findings_include_compliance_mapping_confidence(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Exposure found.",
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Prometheus configuration API exposed without authentication",
                        "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                    }
                ],
            },
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus configuration API exposed without authentication",
                    "tool": "nuclei",
                    "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                    "compliance_mappings": [
                        {
                            "reference": "SOC 2 CC6.6 (Vulnerability and Threat Mitigation)",
                            "confidence": "medium",
                        }
                    ],
                }
            ],
            "results": [],
        }
        md = generate_markdown(report)
        summary_start = md.find("\n### Findings")
        methodology_start = md.find("\n## Methodology")
        self.assertGreaterEqual(summary_start, 0)
        self.assertGreater(methodology_start, summary_start)
        summary_block = md[summary_start:methodology_start]
        self.assertIn("Potential Gap: SOC 2 CC6.6 (Vulnerability and Threat Mitigation) (mapping confidence: medium)", summary_block)
        self.assertIn("Mapping Basis: corroborated by nuclei findings", summary_block)

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

    def test_compliance_coverage_matrix_avoids_stale_evidence_sources(self):
        report = {
            "target": "localhost",
            "compliance_profile": "compliance_pci",
            "results": [
                {"tool": "nuclei", "success": True, "data": {}},
                {"tool": "gobuster", "success": True, "data": []},
            ],
            "findings": [],
        }
        md = generate_markdown(report)
        self.assertIn("| Vulnerability Discovery & Exposure Checks | Partial | none |", md)
        self.assertIn("successful runs produced no evidence payload/findings", md)

    def test_compliance_sections_render_for_all_profiles(self):
        for profile_name in sorted(COMPLIANCE_COVERAGE_ROWS.keys()):
            with self.subTest(profile=profile_name):
                report = {
                    "target": "localhost",
                    "compliance_profile": profile_name,
                    "compliance_framework": profile_name,
                    "results": [
                        {"tool": "nmap", "success": True, "command": "nmap localhost -oX - -sV"},
                        {"tool": "nuclei", "success": True, "command": "nuclei -u http://localhost -jsonl"},
                    ],
                    "findings": [],
                }
                md = generate_markdown(report)
                self.assertIn("## Scope & Assumptions", md)
                self.assertIn("## Compliance Coverage Matrix", md)
                self.assertIn("## Not Assessable Automatically", md)
                self.assertIn("Status legend:", md)
                self.assertIn("Control mapping note: mapped controls indicate potential relevance and require manual validation.", md)

    def test_compliance_mapping_wording_is_softened(self):
        report = {
            "target": "localhost",
            "compliance_profile": "compliance_pci",
            "results": [],
            "findings": [
                {
                    "severity": "INFO",
                    "title": "HTTP Missing Security Headers",
                    "tool": "nuclei",
                    "evidence": "http://localhost:8080",
                    "compliance_mappings": [
                        {"reference": "PCI-DSS 4.0 Req 11.3 (Vulnerability Management)", "confidence": "medium"}
                    ],
                }
            ],
        }
        md = generate_markdown(report)
        self.assertIn("Potential Gap: PCI-DSS 4.0 Req 11.3 (Vulnerability Management) (mapping confidence: medium)", md)
        self.assertNotIn("NON-COMPLIANT", md)

    def test_detailed_findings_include_correlated_signals_hints(self):
        report = {
            "target": "localhost",
            "results": [],
            "findings": [
                {
                    "severity": "INFO",
                    "title": "HTTP Missing Security Headers",
                    "tool": "nuclei",
                    "evidence": "http://localhost:8080",
                },
                {
                    "severity": "INFO",
                    "title": "HTTP Missing Security Headers",
                    "tool": "readiness_probe",
                    "evidence": "http://localhost:19090",
                },
            ],
        }
        md = generate_markdown(report)
        self.assertIn("### Correlated Signals", md)
        self.assertIn("HTTP Missing Security Headers: 2 correlated observations across 2 distinct evidence entries", md)

    def test_report_markdown_generation_is_deterministic(self):
        report = {
            "target": "localhost",
            "compliance_profile": "compliance_soc2",
            "summary": {
                "summary": "Deterministic synthesis.",
                "findings": [
                    {"severity": "MEDIUM", "title": "Multiple HTTP services exposed", "evidence": "ports 8080, 9090"},
                    {"severity": "LOW", "title": "Unknown high ports", "evidence": "ports 40000+"},
                ],
            },
            "findings": [
                {"severity": "INFO", "title": "Open port 8080/tcp", "tool": "nmap", "evidence": "http-proxy"},
                {"severity": "INFO", "title": "Open port 9090/tcp", "tool": "nmap", "evidence": "http Golang net/http server"},
            ],
            "results": [
                {"tool": "nmap", "success": True, "command": "nmap localhost -oX - -sV"},
                {"tool": "whatweb", "success": True, "command": "whatweb http://localhost:8080 --log-json -"},
            ],
        }
        md1 = generate_markdown(report)
        md2 = generate_markdown(report)
        self.assertEqual(md1, md2)

    def test_findings_overview_counts_are_stable(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Count check.",
                "findings": [
                    {"severity": "HIGH", "title": "A", "evidence": "a"},
                    {"severity": "LOW", "title": "B", "evidence": "b"},
                ],
            },
            "findings": [
                {"severity": "INFO", "title": "Open port 80/tcp", "tool": "nmap", "evidence": "http"},
                {"severity": "MEDIUM", "title": "Config endpoint exposed", "tool": "nuclei", "evidence": "/config"},
            ],
            "results": [],
        }
        md = generate_markdown(report)
        self.assertIn("| HIGH | 1 |", md)
        self.assertIn("| LOW | 1 |", md)
        self.assertIn("| MEDIUM | 1 |", md)
        self.assertIn("| INFO | 1 |", md)

    def test_write_markdown(self):
        report = {"target": "t", "results": []}
        path = artifact_path("test_md_report.md")
        written = write_markdown(report, path)
        self.assertTrue(Path(written).exists())
        cleanup_artifact(Path(written))


if __name__ == "__main__":
    unittest.main()
