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

    def test_generate_markdown_includes_reproducibility_trace_section(self):
        report = {
            "target": "localhost",
            "results": [],
            "replay_trace": {
                "file": "ai-audit-soc2-20260210-101010-replay.json",
                "markdown_file": "ai-audit-soc2-20260210-101010-replay.md",
                "step_count": 5,
                "version": 1,
            },
        }
        md = generate_markdown(report)
        self.assertIn("## Reproducibility Trace", md)
        self.assertIn("file:", md)
        self.assertIn("markdown_file:", md)
        self.assertIn("step_count: 5", md)
        self.assertIn("version: 1", md)

    def test_generate_markdown_includes_llm_reasoning_trace_section(self):
        report = {
            "target": "localhost",
            "results": [],
            "llm_reasoning_trace": {
                "json_file": "ai-audit-soc2-20260214-000000-llm-trace.json",
                "markdown_file": "ai-audit-soc2-20260214-000000-llm-trace.md",
                "event_count": 6,
                "decision_steps": 2,
                "llm_calls": 3,
                "version": 1,
            },
        }
        md = generate_markdown(report)
        self.assertIn("## LLM Reasoning Trace", md)
        self.assertIn("json_file:", md)
        self.assertIn("markdown_file:", md)
        self.assertIn("llm_event_count: 6", md)
        self.assertIn("decision_steps: 2", md)
        self.assertIn("llm_calls: 3", md)
        self.assertIn("note: captures explicit planner rationale/messages and decisions", md)

    def test_agentic_expansion_includes_replan_decision_trace_highlights(self):
        report = {
            "target": "localhost",
            "results": [],
            "ai_audit": {
                "phase": "baseline+agentic",
                "max_actions": 10,
                "notes": "Planner proposed only baseline-completed web actions; stopping agentic loop.",
                "decision_trace": [
                    {
                        "iteration": 1,
                        "planner": {
                            "candidates": [
                                {"tool": "httpx", "target": "http://localhost:3001", "priority": 5},
                            ]
                        },
                        "replan": {
                            "attempted": True,
                            "reason": "all_candidates_already_covered",
                            "excluded_count": 1,
                        },
                        "planner_replans": [
                            {
                                "candidates": [
                                    {"tool": "nuclei", "target": "http://localhost:3001", "priority": 5},
                                ]
                            }
                        ],
                        "decision": {"result": "stop", "reason": "all_candidates_already_covered"},
                    }
                ],
                "planner": {"type": "tool_calling"},
                "actions": [],
            },
        }
        md = generate_markdown(report)
        self.assertIn("### Decision Trace Highlights", md)
        self.assertIn("step 1: stop (all_candidates_already_covered)", md)
        self.assertIn("initial_candidate: tool=httpx target=http://localhost:3001 priority=5", md)
        self.assertIn("replan: attempted=true reason=all_candidates_already_covered excluded=1", md)
        self.assertIn("replan_candidate: tool=nuclei target=http://localhost:3001 priority=5", md)

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

    def test_summary_severity_reconciles_with_critical_tool_finding(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Supabase key exposure observed.",
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Supabase service role key exposed",
                        "evidence": "Key observed in HTTP response body.",
                    }
                ],
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "title": "Supabase service role key exposed (supabase_audit)",
                    "tool": "supabase_audit",
                    "evidence": "key=eyJ... detected in source=http://localhost:4001",
                    "recommendation": "Rotate service role key immediately.",
                }
            ],
            "results": [],
        }
        md = generate_markdown(report)
        self.assertIn("- **CRITICAL** Supabase service role key exposed", md)
        self.assertIn("| CRITICAL | 1 |", md)

    def test_recommended_next_actions_include_explicit_critical_recommendation(self):
        report = {
            "target": "localhost",
            "summary": {
                "summary": "Critical key exposure observed.",
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "title": "Supabase service role key exposed",
                        "evidence": "key detected in HTTP response",
                        "recommendation": "Immediately rotate the exposed service role key and remove it from client-accessible responses.",
                    }
                ],
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "title": "Supabase service role key exposed (supabase_audit)",
                    "tool": "supabase_audit",
                    "evidence": "key=eyJ... detected in source=http://localhost:4001",
                    "recommendation": "Immediately rotate the exposed service role key and remove it from client-accessible responses.",
                }
            ],
            "results": [],
        }
        md = generate_markdown(report)
        self.assertIn("## Recommended Next Actions", md)
        self.assertIn("Immediately rotate the exposed service role key", md)
        self.assertIn("After remediation, rerun the readiness assessment", md)

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
        self.assertIn("| Vulnerability Discovery & Exposure Checks | Not Assessed | none |", md)
        self.assertIn("basis=inconclusive_signal", md)
        self.assertIn("successful runs produced no evidence payload/findings", md)
        matrix = report.get("compliance_coverage_matrix")
        self.assertIsInstance(matrix, list)
        if isinstance(matrix, list):
            row = next((r for r in matrix if isinstance(r, dict) and r.get("area") == "Vulnerability Discovery & Exposure Checks"), None)
            self.assertIsNotNone(row)
            if isinstance(row, dict):
                self.assertEqual(row.get("status"), "Not Assessed")
                self.assertEqual(row.get("coverage_basis"), "inconclusive_signal")

    def test_access_control_matrix_uses_readiness_probe_checks_signal(self):
        report = {
            "target": "localhost",
            "compliance_profile": "compliance_soc2",
            "results": [
                {
                    "tool": "readiness_probe",
                    "success": True,
                    "command": "internal readiness probes",
                    "data": {
                        "success": True,
                        "findings": [],
                        "checks": [
                            {"name": "listener_scope", "success": True, "wildcard_ports": [5432, 6379]},
                            {"name": "redis_auth_probe", "success": True, "output": "pong"},
                        ],
                    },
                }
            ],
            "findings": [],
        }
        md = generate_markdown(report)
        self.assertIn("| Access Control Exposure Review | Partial | readiness_probe |", md)
        self.assertIn("basis=corroborated_findings", md)
        matrix = report.get("compliance_coverage_matrix")
        self.assertIsInstance(matrix, list)
        if isinstance(matrix, list):
            row = next((r for r in matrix if isinstance(r, dict) and r.get("area") == "Access Control Exposure Review"), None)
            self.assertIsNotNone(row)
            if isinstance(row, dict):
                self.assertEqual(row.get("status"), "Partial")
                self.assertEqual(row.get("evidence_source"), "readiness_probe")
                self.assertEqual(row.get("coverage_basis"), "corroborated_findings")

    def test_access_control_rows_include_readiness_probe_for_all_profiles(self):
        for profile_name, rows in COMPLIANCE_COVERAGE_ROWS.items():
            with self.subTest(profile=profile_name):
                self.assertIsInstance(rows, list)
                access_rows = [r for r in rows if isinstance(r, dict) and "Access" in str(r.get("area", ""))]
                self.assertTrue(access_rows)
                tools = access_rows[0].get("tools")
                self.assertIsInstance(tools, list)
                if isinstance(tools, list):
                    normalized = [str(t).strip().lower() for t in tools]
                    self.assertIn("readiness_probe", normalized)
                    self.assertIn("nuclei", normalized)

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
        actions = report.get("recommended_next_actions")
        self.assertIsInstance(actions, list)
        if isinstance(actions, list):
            self.assertTrue(actions)

    def test_tool_notes_are_deduplicated_with_counts(self):
        report = {
            "target": "localhost",
            "results": [
                {"tool": "wpscan", "success": False, "skipped": True, "reason": "WordPress not detected by whatweb"},
                {"tool": "wpscan", "success": False, "skipped": True, "reason": "WordPress not detected by whatweb"},
                {"tool": "katana", "success": False, "skipped": True, "reason": "Disabled by config (tools.<name>.enabled=false)"},
                {"tool": "katana", "success": False, "skipped": True, "reason": "Disabled by config (tools.<name>.enabled=false)"},
                {"tool": "katana", "success": False, "skipped": True, "reason": "Disabled by config (tools.<name>.enabled=false)"},
                {"tool": "dnsenum", "success": False, "error": "localhost NS record query failed: NXDOMAIN"},
                {"tool": "dnsenum", "success": False, "error": "localhost NS record query failed: NXDOMAIN"},
            ],
        }
        md = generate_markdown(report)
        self.assertIn("- **wpscan**: SKIPPED - WordPress not detected by whatweb (x2)", md)
        self.assertIn("- **katana**: SKIPPED - Disabled by config (tools.<name>.enabled=false) (x3)", md)
        self.assertIn("- **dnsenum**: FAILED - localhost NS record query failed: NXDOMAIN (x2)", md)

    def test_recommended_next_actions_are_profile_aware(self):
        base_summary = {
            "summary": "Action ordering check.",
            "findings": [
                {
                    "severity": "MEDIUM",
                    "title": "Prometheus metrics endpoint exposed",
                    "evidence": "http://localhost:9090/metrics",
                },
                {
                    "severity": "MEDIUM",
                    "title": "Redis reachable without authentication",
                    "evidence": "port 6379",
                },
                {
                    "severity": "MEDIUM",
                    "title": "PostgreSQL exposed",
                    "evidence": "open port 5432/tcp",
                },
                {
                    "severity": "INFO",
                    "title": "HTTP Missing Security Headers",
                    "evidence": "http://localhost:8080",
                },
                {
                    "severity": "INFO",
                    "title": "No TLS on web endpoints",
                    "evidence": "cleartext HTTP only",
                },
            ],
        }
        pci_md = generate_markdown(
            {
                "target": "localhost",
                "compliance_profile": "compliance_pci",
                "summary": base_summary,
                "findings": [],
                "results": [],
            }
        )
        soc2_md = generate_markdown(
            {
                "target": "localhost",
                "compliance_profile": "compliance_soc2",
                "summary": base_summary,
                "findings": [],
                "results": [],
            }
        )
        pci_tls = "Enforce transport security on externally reachable services and validate TLS configuration strength on non-standard service ports."
        pci_monitor = "Restrict monitoring/debug endpoints to trusted admin or monitoring networks only; add authentication/authorization controls where supported."
        self.assertLess(pci_md.find(pci_tls), pci_md.find(pci_monitor))
        self.assertIn("Collect manual evidence for PCI readiness boundaries not automatable here", pci_md)
        self.assertIn("Collect SOC 2 control-operation evidence not assessable by scanning", soc2_md)

    def test_recommended_next_actions_remain_deterministic_with_profile(self):
        report = {
            "target": "localhost",
            "compliance_profile": "compliance_iso",
            "summary": {
                "summary": "Deterministic action list.",
                "findings": [
                    {"severity": "MEDIUM", "title": "Open ports expose service surface", "evidence": "open port 8080/tcp"},
                    {"severity": "INFO", "title": "HTTP Missing Security Headers", "evidence": "http://localhost:8080"},
                    {"severity": "INFO", "title": "No TLS", "evidence": "cleartext HTTP"},
                ],
            },
            "findings": [],
            "results": [],
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
