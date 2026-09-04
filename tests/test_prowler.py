import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from supabash.runner import CommandResult
from supabash.tools.prowler import ProwlerScanner


OCSF_FAILURE = {
    "finding_info": {
        "title": "S3 bucket should block public access",
        "desc": "Public access is not fully blocked.",
    },
    "metadata": {"event_code": "s3_bucket_level_public_access_block"},
    "severity": "High",
    "status": "New",
    "status_code": "FAIL",
    "status_detail": "Bucket public access block is incomplete.",
    "cloud": {"account": {"uid": "123456789012"}, "region": "eu-west-1"},
    "resources": [{"uid": "arn:aws:s3:::public-bucket", "name": "public-bucket"}],
    "remediation": {"desc": "Enable every public access block setting."},
}

OCSF_PASS = {
    "finding_info": {"title": "CloudTrail is enabled"},
    "metadata": {"event_code": "cloudtrail_enabled"},
    "severity": "Medium",
    "status": "New",
    "status_code": "PASS",
    "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1"},
    "resources": [{"uid": "trail/default"}],
}

ASFF_FAILURE = {
    "AwsAccountId": "210987654321",
    "GeneratorId": "prowler-iam_root_mfa_enabled",
    "Title": "Root account should have MFA enabled",
    "Description": "MFA is not enabled for the root account.",
    "Severity": {"Label": "CRITICAL"},
    "Compliance": {"Status": "FAILED"},
    "Resources": [
        {
            "Id": "arn:aws:iam::210987654321:root",
            "Region": "global",
        }
    ],
    "Remediation": {
        "Recommendation": {"Text": "Enable a hardware MFA device for root."}
    },
}


class TestProwlerScanner(unittest.TestCase):
    def setUp(self):
        self.runner = MagicMock()
        self.scanner = ProwlerScanner(runner=self.runner)

    def test_scan_uses_prowler_five_provider_scoped_ocsf_command(self):
        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "prowler.ocsf.json").write_text("[]", encoding="utf-8")
            return CommandResult(
                command="prowler aws",
                return_code=0,
                stdout="",
                stderr="",
                success=True,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(
                output_dir=directory,
                arguments='--profile "security audit" --severity high',
                timeout_seconds=90,
            )

        command = self.runner.run.call_args.args[0]
        self.assertEqual(command[:2], ["prowler", "aws"])
        self.assertIn("--output-formats", command)
        self.assertEqual(command[command.index("--output-formats") + 1], "json-ocsf")
        self.assertIn("--output-directory", command)
        self.assertNotIn("-O", command)
        self.assertIn("--ignore-exit-code-3", command)
        self.assertIn("security audit", command)
        self.assertEqual(self.runner.run.call_args.kwargs["timeout"], 90)
        self.assertTrue(result["success"])
        self.assertTrue(result["scan_data"]["coverage_complete"])

    def test_successful_exit_without_json_artifact_is_not_reported_clean(self):
        self.runner.run.return_value = CommandResult(
            command="prowler aws",
            return_code=0,
            stdout="completed without output",
            stderr="",
            success=True,
        )

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        self.assertFalse(result["success"])
        self.assertIn("no parseable JSON result artifact", result["error"])
        self.assertEqual(result["raw_output"], "completed without output")
        self.assertFalse(result["scan_data"]["coverage_complete"])
        self.assertEqual(
            result["scan_data"]["parse_diagnostics"][0]["status"], "missing"
        )

    def test_malformed_artifact_preserves_parse_diagnostics(self):
        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "prowler.ocsf.json").write_text(
                "{ definitely-not-json", encoding="utf-8"
            )
            return CommandResult(
                command="prowler aws",
                return_code=0,
                stdout="",
                stderr="",
                success=True,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        self.assertFalse(result["success"])
        diagnostics = result["scan_data"]["parse_diagnostics"]
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["status"], "ignored")
        self.assertIn("neither valid JSON nor valid JSONL", diagnostics[0]["message"])
        self.assertGreater(diagnostics[0]["ignored_line_count"], 0)
        self.assertTrue(diagnostics[0]["errors"])

    def test_partial_jsonl_preserves_warning_and_marks_coverage_incomplete(self):
        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "prowler.ocsf.json").write_text(
                f"{json.dumps(OCSF_FAILURE)}\nnot-json\n", encoding="utf-8"
            )
            return CommandResult(
                command="prowler aws",
                return_code=0,
                stdout="",
                stderr="",
                success=True,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        self.assertTrue(result["success"])
        self.assertFalse(result["scan_data"]["coverage_complete"])
        self.assertEqual(len(result["scan_data"]["findings"]), 1)
        diagnostic = result["scan_data"]["parse_diagnostics"][0]
        self.assertEqual(diagnostic["status"], "parsed_with_warnings")
        self.assertEqual(diagnostic["ignored_line_count"], 1)
        self.assertEqual(diagnostic["errors"][0]["line"], 2)

    def test_reused_output_root_does_not_mix_stale_json(self):
        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "current.ocsf.json").write_text("[]", encoding="utf-8")
            return CommandResult(
                command="prowler aws",
                return_code=0,
                stdout="",
                stderr="",
                success=True,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            stale_path = output_root / "stale.ocsf.json"
            stale_path.write_text(json.dumps(OCSF_FAILURE), encoding="utf-8")

            result = self.scanner.scan(output_dir=directory)

            run_dir = Path(result["scan_data"]["output_dir"])
            self.assertEqual(run_dir.parent, output_root)
            self.assertNotEqual(run_dir, output_root)
            self.assertNotIn(str(stale_path), result["scan_data"]["results_paths"])

        self.assertTrue(result["success"])
        self.assertEqual(result["scan_data"]["findings"], [])

    def test_load_results_accepts_jsonl_starting_with_an_object(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prowler.ocsf.json"
            path.write_text(
                "\n".join(json.dumps(item) for item in (OCSF_FAILURE, OCSF_PASS)),
                encoding="utf-8",
            )

            records, paths = self.scanner._load_results(Path(directory))

        self.assertEqual(records, [OCSF_FAILURE, OCSF_PASS])
        self.assertEqual(paths, [path])

    def test_extract_findings_normalizes_ocsf_and_filters_passes(self):
        findings = self.scanner._extract_findings([OCSF_FAILURE, OCSF_PASS])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["title"], "S3 bucket should block public access")
        self.assertEqual(finding["check_id"], "s3_bucket_level_public_access_block")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["resource"], "arn:aws:s3:::public-bucket")
        self.assertIn("account=123456789012", finding["evidence"])
        self.assertIn("region=eu-west-1", finding["evidence"])
        self.assertIn("status=fail", finding["evidence"])
        self.assertEqual(
            finding["remediation"], "Enable every public access block setting."
        )

    def test_extract_findings_normalizes_asff(self):
        findings = self.scanner._extract_findings([ASFF_FAILURE])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["title"], "Root account should have MFA enabled")
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["check_id"], "prowler-iam_root_mfa_enabled")
        self.assertIn("account=210987654321", finding["evidence"])
        self.assertIn("region=global", finding["evidence"])
        self.assertIn("status=failed", finding["evidence"])
        self.assertEqual(
            finding["description"], "MFA is not enabled for the root account."
        )
        self.assertEqual(
            finding["remediation"], "Enable a hardware MFA device for root."
        )

    def test_loader_ignores_non_ocsf_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prowler.json"
            path.write_text(
                json.dumps({"Findings": [ASFF_FAILURE]}), encoding="utf-8"
            )

            records, paths = self.scanner._load_results(Path(directory))

        self.assertEqual(records, [])
        self.assertEqual(paths, [])

    def test_arbitrary_json_object_is_not_accepted_as_clean_ocsf_evidence(self):
        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "unrelated.ocsf.json").write_text("{}", encoding="utf-8")
            return CommandResult(
                command="prowler aws",
                return_code=0,
                stdout="",
                stderr="",
                success=True,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        self.assertFalse(result["success"])
        self.assertFalse(result["scan_data"]["coverage_complete"])
        self.assertEqual(result["scan_data"]["results_paths"], [])
        self.assertEqual(
            result["scan_data"]["parse_diagnostics"][0]["rejected_record_count"],
            1,
        )

    def test_failed_process_cannot_claim_complete_coverage_with_valid_partial_artifact(self):
        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "partial.ocsf.json").write_text("[]", encoding="utf-8")
            return CommandResult(
                command="prowler aws",
                return_code=2,
                stdout="partial",
                stderr="failed",
                success=False,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        self.assertFalse(result["success"])
        self.assertFalse(result["scan_data"]["coverage_complete"])

    def test_large_scan_exposes_normalization_truncation_and_counts(self):
        records = []
        for index in range(ProwlerScanner.MAX_NORMALIZED_FINDINGS + 1):
            item = json.loads(json.dumps(OCSF_FAILURE))
            item["metadata"]["event_code"] = f"check-{index}"
            records.append(item)

        def run(command, **_kwargs):
            out_dir = Path(command[command.index("--output-directory") + 1])
            (out_dir / "large.ocsf.json").write_text(
                json.dumps(records), encoding="utf-8"
            )
            return CommandResult(
                command="prowler aws",
                return_code=0,
                stdout="",
                stderr="",
                success=True,
            )

        self.runner.run.side_effect = run

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        scan_data = result["scan_data"]
        self.assertTrue(result["success"])
        self.assertEqual(scan_data["finding_count"], len(records))
        self.assertEqual(
            scan_data["normalized_finding_count"],
            ProwlerScanner.MAX_NORMALIZED_FINDINGS,
        )
        self.assertTrue(scan_data["findings_truncated"])
        self.assertFalse(scan_data["coverage_complete"])

    def test_scan_failure_preserves_diagnostics(self):
        self.runner.run.return_value = CommandResult(
            command="prowler aws",
            return_code=2,
            stdout="partial output",
            stderr="invalid arguments",
            success=False,
        )

        with tempfile.TemporaryDirectory() as directory:
            result = self.scanner.scan(output_dir=directory)

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "invalid arguments")
        self.assertEqual(result["raw_output"], "partial output")


if __name__ == "__main__":
    unittest.main()
