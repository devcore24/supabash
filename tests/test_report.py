import unittest
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.report import generate_markdown, write_markdown


class TestReport(unittest.TestCase):
    def test_generate_markdown_basic(self):
        report = {
            "target": "example.com",
            "results": [
                {"tool": "nmap", "success": True},
                {"tool": "nuclei", "success": False, "error": "fail"},
            ],
            "summary": {
                "summary": "One issue found.",
                "findings": [
                    {"severity": "high", "title": "SQLi", "evidence": "param id injectable", "recommendation": "Use prepared statements"}
                ]
            }
        }
        md = generate_markdown(report)
        self.assertIn("Supabash Audit Report", md)
        self.assertIn("example.com", md)
        self.assertIn("SQLi", md)
        self.assertIn("nmap", md)
        self.assertIn("fail", md)

    def test_write_markdown(self):
        report = {"target": "t", "results": []}
        path = Path("/tmp/test_md_report.md")
        written = write_markdown(report, path)
        self.assertTrue(Path(written).exists())
        Path(written).unlink()


if __name__ == "__main__":
    unittest.main()
