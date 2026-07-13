import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from supabash.report import generate_markdown
from supabash.report_lint import lint_report, write_report_lint_artifacts
from supabash.audit import AuditOrchestrator


class TestReportLint(unittest.TestCase):
    def test_clean_report_passes(self):
        report = {
            "schema_version": "1.0",
            "results": [],
            "target": "localhost",
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus configuration exposed",
                    "tool": "nuclei",
                    "evidence": "http://localhost:9090/api/v1/status/config",
                }
            ],
            "summary": {
                "summary": "A high-risk exposure was validated.",
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Prometheus configuration exposed",
                        "evidence": "http://localhost:9090/api/v1/status/config",
                    }
                ],
            },
        }
        result = lint_report(report)
        self.assertTrue(result["valid"])
        self.assertEqual(result["issue_count"], 0)

    def test_critical_detail_must_be_represented_in_summary(self):
        result = lint_report(
            {
                "findings": [{"severity": "CRITICAL", "title": "Secret exposed"}],
                "summary": {"summary": "Review complete.", "findings": []},
            }
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertFalse(result["valid"])
        self.assertIn("critical_missing_from_summary", codes)

    def test_summary_critical_requires_detailed_support(self):
        result = lint_report(
            {
                "findings": [],
                "summary": {
                    "summary": "Critical issue.",
                    "findings": [{"severity": "CRITICAL", "title": "Unsupported claim"}],
                },
            }
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertIn("summary_critical_without_detail", codes)

    def test_malformed_embedded_authority_is_detected(self):
        result = lint_report(
            {
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Malformed endpoint",
                        "evidence": "http://localhost:3003/127.0.0.1:9090/api/v1/status",
                    }
                ]
            }
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertIn("malformed_url", codes)

    def test_cluster_overview_and_unresolved_state_are_checked(self):
        result = lint_report(
            {
                "finding_clusters": [
                    {
                        "cluster_id": "cluster-1",
                        "severity": "HIGH",
                        "seen_in_agentic": True,
                    }
                ],
                "unresolved_high_risk_clusters": [{"cluster_id": "cluster-1"}],
                "finding_cluster_overview": {"open_high_risk_cluster_count": 2},
            }
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertIn("covered_cluster_marked_unresolved", codes)
        self.assertIn("cluster_overview_count_mismatch", codes)

    def test_dead_discovery_path_is_warned_as_likely_noise(self):
        result = lint_report(
            {
                "schema_version": "1.0",
                "target": "localhost",
                "results": [],
                "findings": [
                    {
                        "severity": "INFO",
                        "title": "Browser discovered URL",
                        "type": "browser_discovery",
                        "evidence": "HTTP 404 for http://localhost:3000/admin",
                    }
                ]
            }
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertTrue(result["valid"])
        self.assertIn("likely_noise_discovery", codes)


    def test_credential_bearing_command_is_rejected(self):
        report = {
            "schema_version": "1.0",
            "target": "localhost",
            "results": [
                {
                    "tool": "hydra",
                    "success": True,
                    "command": "hydra -l admin -p super-secret ssh://localhost",
                }
            ],
            "findings": [],
        }
        result = lint_report(report)
        codes = {item["code"] for item in result["issues"]}
        self.assertFalse(result["valid"])
        self.assertIn("credential_in_command_trace", codes)


    def test_plaintext_result_credentials_are_rejected_without_echoing_values(self):
        report = {
            "schema_version": "1.0",
            "target": "localhost",
            "results": [
                {
                    "tool": "hydra",
                    "success": True,
                    "data": {
                        "success": True,
                        "raw_output": "login: root password: legacy-secret",
                        "found_credentials": [
                            {"login": "root", "password": "legacy-secret"}
                        ],
                    },
                }
            ],
            "findings": [],
        }
        result = lint_report(report)
        codes = {item["code"] for item in result["issues"]}
        self.assertFalse(result["valid"])
        self.assertIn("credential_in_persisted_data", codes)
        self.assertNotIn("legacy-secret", json.dumps(result))

        report["results"][0]["data"] = {
            "success": True,
            "raw_output": "login: root password: ro***et",
            "found_credentials": [
                {"login": "root", "password": "<redacted>"}
            ],
        }
        safe_result = lint_report(report)
        safe_codes = {item["code"] for item in safe_result["issues"]}
        self.assertNotIn("credential_in_persisted_data", safe_codes)

    def test_nested_command_credentials_are_rejected(self):
        report = {
            "schema_version": "1.0",
            "target": "localhost",
            "results": [],
            "findings": [],
            "replay": {
                "commands": [
                    {"argv": "hydra -l admin -p nested-secret ssh://localhost"}
                ]
            },
        }
        result = lint_report(report)
        issues = [
            item
            for item in result["issues"]
            if item["code"] == "credential_in_command_trace"
        ]
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["path"], "replay.commands[0].argv")
        self.assertNotIn("nested-secret", json.dumps(result))

    def test_broken_evidence_reference_is_detected(self):
        result = lint_report(
            {
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "title": "Finding",
                        "evidence_artifact": "evidence/results/missing.json",
                    }
                ],
                "evidence_pack": {
                    "artifacts": [
                        {"tool": "nmap", "path": "evidence/results/000-nmap.json"}
                    ]
                },
            }
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertIn("broken_evidence_reference", codes)

    def test_sidecars_and_markdown_visibility(self):
        report = {"schema_version": "1.0", "target": "localhost", "findings": [], "results": []}
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "audit.json"
            lint_result, metadata = write_report_lint_artifacts(report, output)
            self.assertTrue(lint_result["valid"])
            self.assertIsInstance(metadata, dict)
            json_path = output.parent / metadata["json_file"]
            md_path = output.parent / metadata["markdown_file"]
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            self.assertTrue(json.loads(json_path.read_text(encoding="utf-8"))["valid"])
            lint_payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(lint_payload["source"]["report_file"], "audit.json")
            self.assertEqual(len(lint_payload["source"]["sha256"]), 64)

            rendered = generate_markdown(report)
            self.assertIn("## Report Lint", rendered)
            self.assertIn("audit-lint.json", rendered)
            self.assertIn("audit-lint.md", rendered)

    def test_audit_overwrite_uses_pre_lint_object_provenance(self):
        report = {"schema_version": "1.0", "target": "localhost", "findings": [], "results": []}
        snapshot = json.dumps(
            report,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_hash = hashlib.sha256(snapshot).hexdigest()
        previous_file = b'{"target":"previous-run"}'

        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "audit.json"
            output.write_bytes(previous_file)
            orchestrator = AuditOrchestrator(scanners={}, llm_client=None)
            orchestrator._attach_report_artifacts = lambda agg, path: None

            orchestrator._persist_final_report(report, output)

            lint_payload = json.loads(
                (output.parent / "audit-lint.json").read_text(encoding="utf-8")
            )
            source = lint_payload["source"]
            self.assertEqual(source["hash_scope"], "pre_lint_report_object")
            self.assertEqual(source["sha256"], expected_hash)
            self.assertNotEqual(source["sha256"], hashlib.sha256(previous_file).hexdigest())

    def test_existing_report_defaults_to_source_file_provenance(self):
        report = {"schema_version": "1.0", "target": "localhost", "findings": [], "results": []}
        source_file = b'{"schema_version":"1.0","target":"existing","findings":[],"results":[]}'

        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "audit.json"
            output.write_bytes(source_file)

            lint_result, _ = write_report_lint_artifacts(report, output)

            self.assertEqual(lint_result["source"]["hash_scope"], "source_file")
            self.assertEqual(
                lint_result["source"]["sha256"],
                hashlib.sha256(source_file).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
