import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from supabash.report_paths import build_report_paths


class TestReportPaths(unittest.TestCase):
    def test_default_paths(self):
        now = datetime(2025, 12, 13, 12, 34, 56)
        out_path, md_path = build_report_paths(None, None, now=now)
        self.assertEqual(out_path.as_posix(), "reports/report-20251213-123456/report-20251213-123456.json")
        self.assertEqual(md_path.as_posix(), "reports/report-20251213-123456/report-20251213-123456.md")

    def test_default_paths_custom_basename(self):
        now = datetime(2025, 12, 13, 12, 34, 56)
        out_path, md_path = build_report_paths(None, None, now=now, default_basename="ai-audit")
        self.assertEqual(out_path.as_posix(), "reports/ai-audit-20251213-123456/ai-audit-20251213-123456.json")
        self.assertEqual(md_path.as_posix(), "reports/ai-audit-20251213-123456/ai-audit-20251213-123456.md")

    def test_output_suffix_added(self):
        now = datetime(2025, 12, 13, 12, 34, 56)
        out_path, md_path = build_report_paths("reports/my-report", None, now=now)
        self.assertEqual(out_path.as_posix(), "reports/my-report.json")
        self.assertEqual(md_path.as_posix(), "reports/my-report.md")

    def test_output_directory_existing(self):
        now = datetime(2025, 12, 13, 12, 34, 56)
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            out_path, md_path = build_report_paths(d, None, now=now)
            self.assertEqual(out_path, d / "report-20251213-123456.json")
            self.assertEqual(md_path, d / "report-20251213-123456.md")

    def test_markdown_directory_existing(self):
        now = datetime(2025, 12, 13, 12, 34, 56)
        with tempfile.TemporaryDirectory() as td_out, tempfile.TemporaryDirectory() as td_md:
            out_dir = Path(td_out)
            md_dir = Path(td_md)
            out_path, md_path = build_report_paths(out_dir, md_dir, now=now)
            self.assertEqual(out_path, out_dir / "report-20251213-123456.json")
            self.assertEqual(md_path, md_dir / "report-20251213-123456.md")


if __name__ == "__main__":
    unittest.main()
