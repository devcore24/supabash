import sys
import types
import unittest
from pathlib import Path

from supabash.report_export import export_from_markdown_file, markdown_to_html
from tests.test_artifacts import artifact_path, cleanup_artifact


class TestReportExport(unittest.TestCase):
    def test_markdown_to_html_marks_tools_run_table(self):
        md = (
            "## Tools Run\n\n"
            "| Tool | Status | Command |\n"
            "|---|---|---|\n"
            "| nmap | success | `nmap localhost` |\n\n"
            "## Commands Executed\n"
        )
        html = markdown_to_html(md)
        self.assertIn('<table class="tools-run-table">', html)

    def test_export_is_noop_when_disabled(self):
        p = artifact_path("report_export_noop.md")
        p.write_text("# Hi", encoding="utf-8")
        out = export_from_markdown_file(p, config={"core": {"report_exports": {"html": False, "pdf": False}}})
        self.assertIsNone(out.html_path)
        self.assertIsNone(out.pdf_path)
        cleanup_artifact(p)

    def test_export_writes_html_and_pdf_with_fake_modules(self):
        p = artifact_path("report_export.md")
        p.write_text("# Title\n\n| A | B |\n|---|---|\n| 1 | 2 |\n", encoding="utf-8")

        fake_markdown = types.SimpleNamespace(markdown=lambda text, extensions=None, output_format=None: "<h1>Title</h1>")

        class FakeHTML:
            def __init__(self, string: str, base_url: str = ""):
                self.string = string
                self.base_url = base_url

            def write_pdf(self, target: str, stylesheets=None):
                Path(target).write_bytes(b"%PDF-FAKE")

        fake_weasyprint = types.SimpleNamespace(HTML=FakeHTML)

        old_md = sys.modules.get("markdown")
        old_wp = sys.modules.get("weasyprint")
        sys.modules["markdown"] = fake_markdown
        sys.modules["weasyprint"] = fake_weasyprint
        try:
            out = export_from_markdown_file(
                p,
                config={"core": {"report_exports": {"html": True, "pdf": True}}},
            )
            self.assertIsNotNone(out.html_path)
            self.assertTrue(out.html_path.exists())
            self.assertIsNotNone(out.pdf_path)
            self.assertTrue(out.pdf_path.exists())
        finally:
            if old_md is None:
                sys.modules.pop("markdown", None)
            else:
                sys.modules["markdown"] = old_md
            if old_wp is None:
                sys.modules.pop("weasyprint", None)
            else:
                sys.modules["weasyprint"] = old_wp
            cleanup_artifact(p)
            cleanup_artifact(p.with_suffix(".html"))
            cleanup_artifact(p.with_suffix(".pdf"))


if __name__ == "__main__":
    unittest.main()
