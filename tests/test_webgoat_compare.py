import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.webgoat_compare import compare_report_to_baseline


class TestWebGoatComparator(unittest.TestCase):
    def test_compare_report_to_baseline_matches_expected_topics(self):
        report = {
            "target": "http://127.0.0.1:3003/WebGoat",
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "SQL Injection detected in login endpoint",
                    "evidence": "Payload resulted in SQL error and auth bypass",
                    "tool": "nuclei",
                },
                {
                    "severity": "MEDIUM",
                    "title": "Reflected Cross Site Scripting",
                    "evidence": "Reflected payload <script>alert(1)</script>",
                    "tool": "manual",
                },
                {
                    "severity": "INFO",
                    "title": "Open port 8080/tcp",
                    "evidence": "Tomcat detected",
                    "tool": "nmap",
                },
            ],
        }
        baseline = {
            "lesson_modules": [
                "sqlinjection",
                "xss",
                "xxe",
                "webgoatintroduction",
            ],
            "wiki_main_exploit_sections": [
                "SQL Injection, Lesson 7 Exercise",
                "Cross Site Scripting, Lesson 13 Exercise",
                "XXE, Lesson 3 Exercise",
            ],
        }

        result = compare_report_to_baseline(report, baseline)

        self.assertEqual(result["coverage"]["exploit_modules_total"], 3)
        self.assertEqual(result["coverage"]["exploit_modules_matched"], 2)
        self.assertIn("sqlinjection", result["coverage"]["matched_exploit_modules"])
        self.assertIn("xss", result["coverage"]["matched_exploit_modules"])
        self.assertIn("xxe", result["coverage"]["missing_exploit_modules"])
        self.assertEqual(result["totals"]["high_critical_total"], 1)
        self.assertEqual(result["totals"]["high_critical_matched"], 1)
        self.assertGreater(result["score"]["overall_0_100"], 0)


if __name__ == "__main__":
    unittest.main()
