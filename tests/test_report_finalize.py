import json
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from supabash.audit import AuditOrchestrator
from supabash.report_finalize import (
    atomic_write_report_json,
    attach_evidence_artifact_references,
    finalize_report_content,
)


class TestReportFinalize(unittest.TestCase):
    def test_shared_content_finalization_builds_summary_metrics_and_actions(self):
        report = {
            "target": "localhost",
            "results": [],
            "llm": {"calls": [{"error": "invalid JSON"}]},
        }
        findings = [{"severity": "HIGH", "title": "Exposure", "tool": "nuclei"}]
        finalize_report_content(
            report,
            findings,
            "compliance_soc2",
            finding_metrics_builder=lambda values: {"total_findings": len(values)},
            finished_at=20.0,
        )
        self.assertEqual(report["finished_at"], 20.0)
        self.assertEqual(report["finding_metrics"]["total_findings"], 1)
        self.assertIn("summary", report)
        self.assertTrue(report["recommended_next_actions"])
        self.assertIn("compliance_coverage_matrix", report)

    def test_evidence_references_are_attached_by_tool(self):
        report = {
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Exposure",
                    "tool": "nuclei",
                    "corroborating_tools": ["readiness_probe"],
                }
            ],
            "evidence_pack": {
                "artifacts": [
                    {"tool": "nuclei", "status": "success", "path": "evidence/results/001-nuclei.json"},
                    {
                        "tool": "readiness_probe",
                        "status": "success",
                        "path": "evidence/results/002-readiness.json",
                    },
                    {"tool": "nmap", "status": "skipped", "path": "evidence/results/000-nmap.json"},
                ]
            },
        }
        attach_evidence_artifact_references(report)
        self.assertEqual(
            report["findings"][0]["evidence_artifacts"],
            ["evidence/results/001-nuclei.json", "evidence/results/002-readiness.json"],
        )

    def test_atomic_json_write_persists_complete_report(self):
        with TemporaryDirectory(dir="/tmp") as td:
            output = Path(td) / "report.json"
            atomic_write_report_json({"target": "localhost", "saved_to": str(output)}, output)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["saved_to"], str(output))
            self.assertFalse(list(output.parent.glob("*.tmp")))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_persistence_redacts_credentials_from_report_and_evidence(self):
        report = {
            "schema_version": "1.0",
            "target": "localhost",
            "results": [
                {
                    "tool": "hydra",
                    "success": True,
                    "data": {
                        "success": True,
                        "raw_output": (
                            "host: localhost login: root password: persisted-secret"
                        ),
                        "found_credentials": [
                            {
                                "host": "localhost",
                                "login": "root",
                                "password": "persisted-secret",
                            }
                        ],
                    },
                }
            ],
            "findings": [],
        }
        orchestrator = AuditOrchestrator(
            scanners={"dummy": object()},
            llm_client=object(),
        )
        with TemporaryDirectory(dir="/tmp") as td:
            output = Path(td) / "report.json"
            orchestrator._persist_final_report(report, output)
            persisted_json = "\n".join(
                path.read_text(encoding="utf-8")
                for path in Path(td).rglob("*.json")
            )
            self.assertNotIn("persisted-secret", persisted_json)
            self.assertIn("<redacted>", persisted_json)
            written_files = [
                path for path in Path(td).rglob("*") if path.is_file()
            ]
            self.assertTrue(written_files)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in written_files))


    def test_artifact_failure_message_is_redacted_before_persistence(self):
        class FailingArtifactsOrchestrator(AuditOrchestrator):
            def _attach_report_artifacts(self, agg, output):
                raise RuntimeError("artifact password=artifact-secret")

        report = {
            "schema_version": "1.0",
            "target": "localhost",
            "results": [],
            "findings": [],
        }
        orchestrator = FailingArtifactsOrchestrator(
            scanners={"dummy": object()},
            llm_client=object(),
        )
        with TemporaryDirectory() as td:
            output = Path(td) / "report.json"
            persisted = orchestrator._persist_final_report(report, output)
            serialized = output.read_text(encoding="utf-8")
            self.assertNotIn("artifact-secret", serialized)
            self.assertNotIn("artifact-secret", json.dumps(persisted))
            self.assertIn("<redacted>", persisted["artifact_write_error"])


if __name__ == "__main__":
    unittest.main()
