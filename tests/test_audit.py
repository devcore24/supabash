import unittest
import json
from pathlib import Path
import sys
import os
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.audit import AuditOrchestrator
from tests.test_artifacts import artifact_path, cleanup_artifact


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


class FakeDnsenumScanner:
    def __init__(self):
        self.called = False

    def scan(self, *args, **kwargs):
        self.called = True
        return {"success": True, "scan_data": {"raw_output": "dnsenum ok"}}


class FakeHttpxVersionScanner:
    def _resolve_httpx_binary(self):
        return "/usr/local/bin/httpx"


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
        output = artifact_path("audit_test.json")
        report = orchestrator.run("example.com", output, container_image="alpine:latest")
        self.assertTrue(output.exists())
        data = json.loads(output.read_text())
        self.assertEqual(data["target"], "example.com")
        self.assertIn("schema_version", data)
        self.assertIn("schema_validation", data)
        self.assertEqual(data["container_image"], "alpine:latest")
        self.assertIn("evidence_pack", data)
        evidence_pack = data.get("evidence_pack", {})
        manifest_rel = evidence_pack.get("manifest")
        self.assertIsInstance(manifest_rel, str)
        if isinstance(manifest_rel, str):
            manifest_path = output.parent / manifest_rel
            self.assertTrue(manifest_path.exists())
        # ensure all tools ran
        tool_names = [r["tool"] for r in data["results"]]
        self.assertIn("trivy", tool_names)
        self.assertIn("findings", data)
        self.assertGreaterEqual(len(data["findings"]), 1)
        cleanup_artifact(output)

    def test_web_targets_include_http_service_on_nonstandard_port(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        urls = orch._web_targets_from_nmap(
            "localhost",
            {
                "hosts": [
                    {
                        "ip": "127.0.0.1",
                        "ports": [
                            {"port": 6000, "protocol": "tcp", "service": "http", "state": "open"},
                            {"port": 9100, "protocol": "tcp", "service": "jetdirect", "state": "open"},
                        ],
                    }
                ]
            },
        )
        self.assertIn("http://localhost:6000", urls)
        self.assertNotIn("http://localhost:9100", urls)

    def test_web_targets_include_http_candidates_when_service_fingerprinting_is_wrong(self):
        """
        nmap service detection can mislabel common web ports (e.g. :3000, :5050).
        We still want to feed those ports into httpx for confirmation so we don't miss web apps.
        """
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        urls = orch._web_targets_from_nmap(
            "localhost",
            {
                "hosts": [
                    {
                        "ip": "127.0.0.1",
                        "ports": [
                            {"port": 3000, "protocol": "tcp", "service": "ppp", "state": "open"},
                            {"port": 5050, "protocol": "tcp", "service": "mmcc", "state": "open"},
                        ],
                    }
                ]
            },
        )
        self.assertIn("http://localhost:3000", urls)
        self.assertIn("http://localhost:5050", urls)

    def test_tls_candidate_ports_include_nonstandard_tls_ports(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        ports = orch._tls_candidate_ports_from_nmap(
            {
                "hosts": [
                    {
                        "ports": [
                            {"port": 8080, "protocol": "tcp", "service": "http", "state": "open"},
                            {"port": 9443, "protocol": "tcp", "service": "https-alt", "state": "open"},
                            {"port": 10443, "protocol": "tcp", "service": "http", "state": "open"},
                            {"port": 8443, "protocol": "tcp", "service": "https", "state": "closed"},
                        ]
                    }
                ]
            },
            web_targets=["https://localhost:10443", "http://localhost:8080"],
        )
        self.assertIn(9443, ports)
        self.assertIn(10443, ports)
        self.assertNotIn(8080, ports)
        self.assertNotIn(8443, ports)

    def test_prioritize_web_targets_for_deep_scan_prefers_risk_ports_and_caps(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        ranked = orch._prioritize_web_targets_for_deep_scan(
            [
                "http://localhost:3000",
                "http://localhost:9090",
                "http://localhost:8080",
                "https://localhost:8443",
                "http://localhost:19090",
            ],
            max_targets=3,
        )
        self.assertEqual(
            ranked,
            [
                "https://localhost:8443",
                "http://localhost:3000",
                "http://localhost:8080",
            ],
        )

    def test_collect_findings_includes_readiness_probe_results(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        agg = {
            "results": [
                {
                    "tool": "readiness_probe",
                    "success": True,
                    "data": {
                        "findings": [
                            {
                                "severity": "MEDIUM",
                                "title": "Redis reachable without authentication",
                                "evidence": "redis-cli PING returned PONG",
                                "type": "redis_auth_exposure",
                            },
                            {
                                "severity": "LOW",
                                "title": "Debug endpoint accessible without authentication",
                                "evidence": "http://localhost/debug/vars (HTTP 200)",
                                "type": "debug_endpoint_exposure",
                            },
                        ]
                    },
                }
            ]
        }
        findings = orch._collect_findings(agg)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["tool"], "readiness_probe")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

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
        output = artifact_path("audit_fail.json")
        report = orchestrator.run("example.com", output)
        failures = [r for r in report["results"] if not r["success"]]
        self.assertTrue(failures)
        nmap_entry = next((r for r in report["results"] if r.get("tool") == "nmap"), None)
        self.assertIsNotNone(nmap_entry)
        self.assertEqual(nmap_entry.get("error"), "fail")
        cleanup_artifact(output)

    def test_compliance_coverage_matrix_is_added_to_report_json(self):
        scanners = {
            "nmap": FakeScanner("nmap"),
            "nuclei": FakeScanner("nuclei"),
            "whatweb": FakeScanner("whatweb"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
        }
        class FakeLLM:
            def chat(self, messages, temperature=0.2):
                return '{"summary":"ok","findings":[]}'

        orchestrator = AuditOrchestrator(scanners=scanners, llm_client=FakeLLM())
        output = artifact_path("audit_compliance_matrix.json")
        report = orchestrator.run("localhost", output, use_llm=False, compliance_profile="soc2")
        matrix = report.get("compliance_coverage_matrix")
        self.assertIsInstance(matrix, list)
        if isinstance(matrix, list) and matrix:
            first = matrix[0]
            self.assertIsInstance(first, dict)
            if isinstance(first, dict):
                self.assertIn("area", first)
                self.assertIn("status", first)
                self.assertIn("evidence_source", first)
                self.assertIn("notes", first)
                self.assertIn("coverage_basis", first)
        data = json.loads(output.read_text())
        self.assertIsInstance(data.get("compliance_coverage_matrix"), list)
        self.assertIsInstance(data.get("recommended_next_actions"), list)
        if isinstance(data.get("recommended_next_actions"), list):
            self.assertTrue(data.get("recommended_next_actions"))
        cleanup_artifact(output)

    def test_dnsenum_is_skipped_for_localhost_targets(self):
        dnsenum_scanner = FakeDnsenumScanner()
        scanners = {
            "nmap": FakeScanner("nmap"),
            "dnsenum": dnsenum_scanner,
        }
        class FakeLLM:
            def chat(self, messages, temperature=0.2):
                return '{"summary":"ok","findings":[]}'

        orchestrator = AuditOrchestrator(scanners=scanners, llm_client=FakeLLM())
        output = artifact_path("audit_localhost_dns_skip.json")
        report = orchestrator.run("localhost", output, use_llm=False)
        dnsenum_entry = next((r for r in report["results"] if r.get("tool") == "dnsenum"), None)
        self.assertIsNotNone(dnsenum_entry)
        self.assertTrue(bool(dnsenum_entry.get("skipped")))
        self.assertEqual(dnsenum_entry.get("reason"), "Localhost/loopback target (DNS enumeration N/A)")
        self.assertFalse(dnsenum_scanner.called)
        cleanup_artifact(output)

    def test_promote_subfinder_hosts_filters_scope_and_resolved_only(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        orch.llm = SimpleNamespace(
            config=SimpleNamespace(
                config={
                    "tools": {
                        "subfinder": {
                            "max_candidates": 20,
                            "max_promoted_hosts": 5,
                            "resolve_validation": True,
                        }
                    }
                }
            )
        )

        def fake_resolve(host, max_ips=4):
            mapping = {
                "api.example.com": ["203.0.113.10"],
                "example.com": ["203.0.113.11"],
            }
            return mapping.get(str(host), [])

        orch._resolve_host_ips = fake_resolve  # type: ignore[assignment]
        promoted = orch._promote_subfinder_hosts(
            "api.example.com",
            ["api.example.com", "www.example.com", "evil.attacker.net", "example.com"],
        )
        self.assertIsInstance(promoted, dict)
        urls = promoted.get("urls") if isinstance(promoted, dict) else []
        self.assertIn("http://api.example.com", urls)
        self.assertIn("https://api.example.com", urls)
        self.assertIn("http://example.com", urls)
        self.assertNotIn("http://evil.attacker.net", urls)
        stats = promoted.get("stats", {}) if isinstance(promoted, dict) else {}
        self.assertEqual(int(stats.get("discovered", 0)), 4)
        self.assertEqual(int(stats.get("in_scope", 0)), 3)
        self.assertEqual(int(stats.get("resolved", 0)), 2)
        self.assertEqual(int(stats.get("promoted_hosts", 0)), 2)

    def test_fast_port_discovery_scopes_nmap_ports(self):
        class CaptureNmapScanner:
            def __init__(self):
                self.calls = []

            def scan(self, target, ports=None, arguments=None, **kwargs):
                self.calls.append({"target": target, "ports": ports, "arguments": arguments})
                open_ports = [22, 8080] if ports else [22, 8080, 9090]
                return {
                    "success": True,
                    "command": "nmap test",
                    "scan_data": {
                        "hosts": [
                            {
                                "ports": [
                                    {
                                        "port": p,
                                        "protocol": "tcp",
                                        "state": "open",
                                        "service": "http" if p in (8080, 9090) else "ssh",
                                    }
                                    for p in open_ports
                                ]
                            }
                        ]
                    },
                }

        class FakeRustscanScanner:
            def scan(self, target, ports="1-65535", batch=2000, arguments=None, **kwargs):
                return {
                    "success": True,
                    "command": "rustscan test",
                    "scan_data": {
                        "hosts": [
                            {
                                "ports": [
                                    {"port": 22, "protocol": "tcp", "state": "open"},
                                    {"port": 8080, "protocol": "tcp", "state": "open"},
                                ]
                            }
                        ]
                    },
                }

        class FakeHttpxScanner:
            def scan(self, targets, **kwargs):
                alive = [str(x) for x in (targets or []) if str(x).startswith("http://")]
                return {"success": True, "command": "httpx test", "alive": alive}

        scanners = {
            "nmap": CaptureNmapScanner(),
            "rustscan": FakeRustscanScanner(),
            "httpx": FakeHttpxScanner(),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
        }

        orch = AuditOrchestrator(scanners=scanners, llm_client=None)
        output = artifact_path("audit_fast_discovery_scopes_nmap.json")
        report = orch.run("example.com", output, use_llm=False)

        nmap_calls = scanners["nmap"].calls
        self.assertTrue(nmap_calls)
        if nmap_calls:
            self.assertEqual(nmap_calls[0].get("ports"), "22,8080")
        rustscan_entry = next((r for r in report["results"] if r.get("tool") == "rustscan"), None)
        self.assertIsNotNone(rustscan_entry)
        self.assertTrue(bool(rustscan_entry.get("success")))
        cleanup_artifact(output)

    def test_baseline_runs_single_broad_nuclei_pass_for_multiple_targets(self):
        class FakeNmapMultiWeb:
            def scan(self, target, ports=None, arguments=None, **kwargs):
                return {
                    "success": True,
                    "command": "nmap test",
                    "scan_data": {
                        "hosts": [
                            {
                                "ports": [
                                    {"port": 3000, "protocol": "tcp", "state": "open", "service": "http"},
                                    {"port": 3001, "protocol": "tcp", "state": "open", "service": "http"},
                                    {"port": 5050, "protocol": "tcp", "state": "open", "service": "http"},
                                ]
                            }
                        ]
                    },
                }

        class FakeHttpxAlive:
            def scan(self, targets, **kwargs):
                return {"success": True, "command": "httpx test", "alive": [str(t) for t in targets]}

        class CaptureNuclei:
            def __init__(self):
                self.calls = []

            def scan(self, target, **kwargs):
                self.calls.append(target)
                return {"success": True, "command": "nuclei test", "findings": []}

        nuclei_scanner = CaptureNuclei()
        scanners = {
            "nmap": FakeNmapMultiWeb(),
            "httpx": FakeHttpxAlive(),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": nuclei_scanner,
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
        }

        orch = AuditOrchestrator(scanners=scanners, llm_client=None)
        output = artifact_path("audit_broad_nuclei_single_pass.json")
        report = orch.run("localhost", output, use_llm=False)

        self.assertEqual(len(nuclei_scanner.calls), 1)
        if nuclei_scanner.calls:
            self.assertIsInstance(nuclei_scanner.calls[0], list)
            self.assertGreaterEqual(len(nuclei_scanner.calls[0]), 2)
        nuclei_entries = [
            r for r in report.get("results", []) if isinstance(r, dict) and r.get("tool") == "nuclei" and not r.get("skipped")
        ]
        self.assertEqual(len(nuclei_entries), 1)
        cleanup_artifact(output)

    def test_readiness_probe_receives_all_confirmed_web_targets(self):
        class FakeNmapMultiWeb:
            def scan(self, target, ports=None, arguments=None, **kwargs):
                return {
                    "success": True,
                    "command": "nmap test",
                    "scan_data": {
                        "hosts": [
                            {
                                "ports": [
                                    {"port": 3000, "protocol": "tcp", "state": "open", "service": "http"},
                                    {"port": 3001, "protocol": "tcp", "state": "open", "service": "http"},
                                    {"port": 5050, "protocol": "tcp", "state": "open", "service": "http"},
                                    {"port": 8080, "protocol": "tcp", "state": "open", "service": "http"},
                                ]
                            }
                        ]
                    },
                }

        class FakeHttpxAlive:
            def scan(self, targets, **kwargs):
                return {"success": True, "command": "httpx test", "alive": [str(t) for t in targets]}

        scanners = {
            "nmap": FakeNmapMultiWeb(),
            "httpx": FakeHttpxAlive(),
            "whatweb": FakeScanner("whatweb"),
            "nuclei": FakeScanner("nuclei"),
            "gobuster": FakeScanner("gobuster"),
            "sqlmap": FakeScanner("sqlmap"),
        }

        captured = {}
        orch = AuditOrchestrator(scanners=scanners, llm_client=None)

        def fake_readiness(scan_host, web_targets, open_ports):
            captured["scan_host"] = scan_host
            captured["web_targets"] = list(web_targets or [])
            captured["open_ports"] = list(open_ports or [])
            return {"success": True, "command": "internal readiness probes", "findings": [], "checks": [], "commands": []}

        orch._run_readiness_probe = fake_readiness  # type: ignore[assignment]

        output = artifact_path("audit_readiness_probe_target_breadth.json")
        report = orch.run("localhost", output, use_llm=False, compliance_profile="soc2")

        report_targets = report.get("web_targets") if isinstance(report.get("web_targets"), list) else []
        self.assertGreaterEqual(len(report_targets), 4)
        self.assertEqual(sorted(captured.get("web_targets", [])), sorted([str(x) for x in report_targets]))
        cleanup_artifact(output)

    def test_compliance_tagging_avoids_caa_and_soft_maps_vuln_findings(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        findings = [
            {
                "severity": "INFO",
                "title": "CAA Record",
                "tool": "nuclei",
                "evidence": "localhost",
            },
            {
                "severity": "INFO",
                "title": "HTTP Missing Security Headers",
                "tool": "nuclei",
                "evidence": "http://localhost:8080",
            },
        ]
        out = orch._apply_compliance_tags({}, findings, "pci")
        self.assertEqual(len(out), 2)
        caa = out[0]
        headers = out[1]
        self.assertFalse(isinstance(caa.get("compliance_mappings"), list) and len(caa.get("compliance_mappings", [])) > 0)
        mappings = headers.get("compliance_mappings")
        self.assertIsInstance(mappings, list)
        self.assertTrue(mappings)
        if isinstance(mappings, list) and mappings:
            first = mappings[0]
            self.assertEqual(first.get("status"), "potential_gap")
            self.assertEqual(first.get("confidence"), "medium")
            self.assertIn("PCI-DSS 4.0 Req 2", str(first.get("reference")))

    def test_compliance_tagging_maps_readiness_probe_findings(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        findings = [
            {
                "severity": "MEDIUM",
                "title": "Redis reachable without authentication",
                "tool": "readiness_probe",
            },
            {
                "severity": "HIGH",
                "title": "Prometheus config endpoint accessible without authentication",
                "tool": "readiness_probe",
            },
        ]
        out = orch._apply_compliance_tags({}, findings, "soc2")
        self.assertEqual(len(out), 2)
        first_maps = out[0].get("compliance_mappings") or []
        second_maps = out[1].get("compliance_mappings") or []
        self.assertTrue(any(m.get("control_key") == "access_control" for m in first_maps))
        self.assertTrue(any(m.get("control_key") == "access_control" for m in second_maps))
        self.assertTrue(any(m.get("status") == "potential_gap" for m in second_maps))

    def test_compliance_tagging_maps_nmap_database_exposure(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        findings = [
            {
                "severity": "INFO",
                "title": "Open port 5432/tcp",
                "tool": "nmap",
                "evidence": "postgresql PostgreSQL DB 9.6.0 or later",
            }
        ]
        out = orch._apply_compliance_tags({}, findings, "soc2")
        maps = out[0].get("compliance_mappings") or []
        control_keys = {m.get("control_key") for m in maps if isinstance(m, dict)}
        self.assertIn("access_control", control_keys)
        self.assertIn("data_protection", control_keys)

    def test_compliance_tagging_maps_whatweb_posture_signals(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        findings = [
            {
                "severity": "INFO",
                "title": "Tech stack detected",
                "tool": "whatweb",
                "evidence": "Country, IP, X-Powered-By, UncommonHeaders",
            }
        ]
        out = orch._apply_compliance_tags({}, findings, "iso")
        maps = out[0].get("compliance_mappings") or []
        self.assertTrue(any(m.get("control_key") == "secure_config" for m in maps if isinstance(m, dict)))

    def test_compliance_tagging_maps_cloud_findings(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        findings = [
            {
                "severity": "HIGH",
                "title": "S3 bucket publicly accessible without encryption",
                "tool": "scoutsuite",
                "evidence": "bucket=logs-prod, public=true, encryption=disabled",
            }
        ]
        out = orch._apply_compliance_tags({}, findings, "gdpr")
        maps = out[0].get("compliance_mappings") or []
        control_keys = {m.get("control_key") for m in maps if isinstance(m, dict)}
        self.assertIn("secure_config", control_keys)
        self.assertIn("vuln_mgmt", control_keys)
        self.assertIn("data_protection", control_keys)

    def test_extract_tool_version_value_prefers_version_over_banner(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        sample = """
    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
             /_/

        projectdiscovery.io

[INF] Current Version: v1.8.1
"""
        v = orch._extract_tool_version_value("httpx", sample)
        self.assertEqual(v, "v1.8.1")

    def test_extract_tool_version_value_handles_plain_version_line(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)
        self.assertEqual(orch._extract_tool_version_value("gobuster", "3.6\n"), "3.6")

    def test_best_effort_tool_version_returns_none_for_usage_only_output(self):
        orch = AuditOrchestrator(scanners={}, llm_client=None)

        class FakeCompleted:
            def __init__(self, stdout="", stderr=""):
                self.stdout = stdout
                self.stderr = stderr

        with patch("subprocess.run", return_value=FakeCompleted(stdout="Usage: httpx [OPTIONS] URL\n")):
            v = orch._best_effort_tool_version("httpx")
        self.assertIsNone(v)

    def test_version_commands_for_httpx_prefer_resolved_scanner_binary(self):
        orch = AuditOrchestrator(scanners={"httpx": FakeHttpxVersionScanner()}, llm_client=None)
        cmds = orch._version_commands_for_tool("httpx")
        self.assertTrue(cmds)
        self.assertEqual(cmds[0], ["/usr/local/bin/httpx", "-version"])
        self.assertEqual(cmds[1], ["/usr/local/bin/httpx", "--version"])


if __name__ == "__main__":
    unittest.main()
