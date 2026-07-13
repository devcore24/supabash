import unittest

from supabash.benchmark_quality import evaluate_report_quality, validate_expectations


class TestBenchmarkQuality(unittest.TestCase):
    def _report(self, profile="compliance_soc2"):
        return {
            "schema_version": "1.0",
            "target": "localhost",
            "results": [],
            "compliance_profile": profile,
            "started_at": 10.0,
            "finished_at": 14.0,
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus configuration exposed",
                    "risk_class": "unauthenticated_exposure",
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
                    }
                ],
            },
            "ai_audit": {"actions": [{"tool": "browser_use"}]},
            "unresolved_high_risk_clusters": [],
        }

    def test_soc2_quality_gate_passes_expected_fixture(self):
        result = evaluate_report_quality(
            self._report(),
            {
                "min_high_risk_findings": 1,
                "required_risk_classes": ["unauthenticated_exposure"],
                "required_title_contains": ["prometheus"],
                "max_open_high_risk_clusters": 0,
                "max_duration_seconds": 5,
            },
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["metrics"]["duration_seconds"], 4.0)
        self.assertTrue(result["report_lint"]["valid"])

    def test_pci_profile_recomputes_duplicate_rate(self):
        report = self._report("compliance_pci")
        report["finding_metrics"] = {"duplicate_rate": 0.0}
        report["findings"] = report["findings"] * 2
        result = evaluate_report_quality(report)
        self.assertFalse(result["passed"])
        duplicate = next(item for item in result["checks"] if item["name"] == "duplicate_rate")
        self.assertEqual(duplicate["actual"], 0.5)
        self.assertEqual(duplicate["expected"], "<= 0.2")

    def test_gate_reports_missing_expected_signal_and_action_overrun(self):
        report = self._report()
        report["findings"] = []
        report["summary"]["findings"] = []
        report["ai_audit"]["actions"] = [{} for _ in range(4)]
        result = evaluate_report_quality(
            report,
            {
                "max_agentic_actions": 2,
                "min_high_risk_findings": 1,
                "required_risk_classes": ["secret_exposure"],
            },
        )
        self.assertFalse(result["passed"])
        failed = {item["name"] for item in result["checks"] if not item["passed"]}
        self.assertIn("agentic_actions", failed)
        self.assertIn("high_risk_yield", failed)
        self.assertIn("risk_class:secret_exposure", failed)

    def test_malformed_action_records_fail_the_gate(self):
        report = self._report()
        report["ai_audit"]["actions"].append("not-an-object")
        result = evaluate_report_quality(report)
        invalid = next(item for item in result["checks"] if item["name"] == "agentic_actions_valid")
        self.assertFalse(invalid["passed"])
        self.assertEqual(result["metrics"]["malformed_agentic_actions"], 1)

    def test_malformed_actions_container_fails_the_gate(self):
        report = self._report()
        report["ai_audit"]["actions"] = "not-a-list"
        result = evaluate_report_quality(report)
        invalid = next(item for item in result["checks"] if item["name"] == "agentic_actions_valid")
        self.assertFalse(result["passed"])
        self.assertFalse(invalid["passed"])
        self.assertEqual(result["metrics"]["malformed_agentic_actions"], 1)


    def test_duration_and_negative_scenario_budgets(self):
        result = evaluate_report_quality(
            self._report(),
            {
                "max_duration_seconds": 3,
                "max_high_risk_findings": 0,
                "forbidden_risk_classes": ["unauthenticated_exposure"],
                "forbidden_title_contains": ["prometheus"],
            },
        )
        self.assertFalse(result["passed"])
        failed = {item["name"] for item in result["checks"] if not item["passed"]}
        self.assertIn("duration_seconds", failed)
        self.assertIn("max_high_risk_findings", failed)
        self.assertIn("forbidden_risk_class:unauthenticated_exposure", failed)
        self.assertIn("forbidden_title_contains:prometheus", failed)

    def test_duration_gate_requires_measured_runtime(self):
        report = self._report()
        report.pop("started_at")
        report.pop("finished_at")
        result = evaluate_report_quality(report, {"max_duration_seconds": 30})
        duration = next(item for item in result["checks"] if item["name"] == "duration_seconds")
        self.assertFalse(duration["passed"])
        self.assertIsNone(duration["actual"])


    def test_reversed_timestamps_fail_duration_gate(self):
        report = self._report()
        report["started_at"] = 20.0
        report["finished_at"] = 10.0
        result = evaluate_report_quality(report, {"max_duration_seconds": 1})
        duration = next(item for item in result["checks"] if item["name"] == "duration_seconds")
        self.assertFalse(duration["passed"])
        self.assertIsNone(duration["actual"])

    def test_risk_class_gates_recompute_instead_of_trusting_report_label(self):
        report = self._report()
        report["findings"][0].update(
            {
                "title": "Service role key exposed",
                "evidence": "A service role secret was exposed.",
                "risk_class": "surface_discovery",
            }
        )
        result = evaluate_report_quality(
            report,
            {"forbidden_risk_classes": ["secret_exposure"]},
        )
        forbidden = next(
            item for item in result["checks"]
            if item["name"] == "forbidden_risk_class:secret_exposure"
        )
        self.assertFalse(forbidden["passed"])
        self.assertIn("secret_exposure", result["metrics"]["risk_classes"])

    def test_stale_embedded_lint_is_not_trusted(self):
        report = self._report()
        report.pop("schema_version")
        report["report_lint"] = {"valid": True, "counts": {"ERROR": 0}}
        result = evaluate_report_quality(report)
        self.assertFalse(result["passed"])
        self.assertGreater(result["metrics"]["lint_errors"], 0)

    def test_expectations_are_type_checked(self):
        with self.assertRaisesRegex(ValueError, "list of non-empty strings"):
            validate_expectations({"required_risk_classes": "secret_exposure"})
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            validate_expectations({"max_duplicate_rate": 2})
        with self.assertRaisesRegex(ValueError, "unsupported expectation"):
            validate_expectations({"mystery_gate": 1})

    def test_expectation_numbers_require_strict_finite_values(self):
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            validate_expectations({"max_agentic_actions": 1.5})
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            validate_expectations({"max_agentic_actions": "2"})
        with self.assertRaisesRegex(ValueError, "non-negative number"):
            validate_expectations({"max_duration_seconds": float("nan")})
        with self.assertRaisesRegex(ValueError, "non-negative number"):
            validate_expectations({"max_duration_seconds": float("inf")})
        with self.assertRaisesRegex(ValueError, "non-negative number"):
            validate_expectations({"max_duration_seconds": "5"})

    def test_non_mapping_report_fails_cleanly(self):
        result = evaluate_report_quality([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["checks"][0]["name"], "report_object")


if __name__ == "__main__":
    unittest.main()
