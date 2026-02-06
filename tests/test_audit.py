import unittest
import json
from pathlib import Path
import sys
import os

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


if __name__ == "__main__":
    unittest.main()
