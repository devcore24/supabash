import unittest
import json
from pathlib import Path
import sys
import os
from unittest.mock import patch

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
