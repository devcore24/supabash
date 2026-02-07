from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import re


@dataclass
class ExportResult:
    html_path: Optional[Path] = None
    pdf_path: Optional[Path] = None
    html_error: Optional[str] = None
    pdf_error: Optional[str] = None


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    return bool(value)


def _report_exports_config(config: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    cfg = config if isinstance(config, dict) else {}
    core = cfg.get("core", {}) if isinstance(cfg.get("core", {}), dict) else {}
    exports = core.get("report_exports", {}) if isinstance(core.get("report_exports", {}), dict) else {}
    return {
        "html": _bool(exports.get("html"), default=False),
        "pdf": _bool(exports.get("pdf"), default=False),
    }


def _import_markdown():
    import importlib

    return importlib.import_module("markdown")


def _import_weasyprint():
    import importlib

    return importlib.import_module("weasyprint")


def _mark_tools_run_table(html_fragment: str) -> str:
    """
    Add a specific CSS class to the table immediately after the
    "Tools Run" heading so PDF/HTML exports can enforce better
    column widths and command wrapping.
    """
    if not html_fragment:
        return html_fragment
    pattern = re.compile(
        r'(<h2[^>]*id="tools-run"[^>]*>.*?</h2>\s*)<table>',
        flags=re.IGNORECASE | re.DOTALL,
    )
    return pattern.sub(r'\1<table class="tools-run-table">', html_fragment, count=1)


def markdown_to_html(markdown_text: str) -> str:
    md = _import_markdown()
    fn = getattr(md, "markdown", None)
    if not callable(fn):
        raise RuntimeError("markdown module does not provide markdown()")
    # Enable heading IDs so in-document anchors (e.g. #summary) work in the exported HTML/PDF.
    # - toc: generates stable id="" attributes for headings
    # - attr_list: allows explicit heading IDs like "## Summary {#summary}" if we ever want them
    body_html = fn(markdown_text, extensions=["tables", "fenced_code", "toc", "attr_list"], output_format="html5")
    body_html = _mark_tools_run_table(body_html)
    # Render with explicit table/code styling so HTML/PDF exports remain readable
    # for long command rows in "Tools Run".
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      line-height: 1.45;
      margin: 20px;
      color: #111;
    }}
    h1, h2, h3, h4 {{
      margin-top: 1.1em;
      margin-bottom: 0.5em;
    }}
    p, ul, ol {{
      margin: 0.5em 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 0.6em 0 1em 0;
      font-size: 0.95em;
    }}
    th, td {{
      border: 1px solid #cfcfcf;
      padding: 6px 8px;
      vertical-align: top;
      overflow-wrap: break-word;
      word-break: normal;
    }}
    th {{
      background: #f5f5f5;
      text-align: left;
      font-weight: 600;
      white-space: nowrap;
      overflow-wrap: normal;
      word-break: normal;
    }}
    .tools-run-table {{
      table-layout: fixed;
    }}
    .tools-run-table th:nth-child(1),
    .tools-run-table td:nth-child(1) {{
      width: 14%;
    }}
    .tools-run-table th:nth-child(2),
    .tools-run-table td:nth-child(2) {{
      width: 12%;
    }}
    .tools-run-table th:nth-child(3),
    .tools-run-table td:nth-child(3) {{
      width: 74%;
    }}
    .tools-run-table td:nth-child(2) {{
      white-space: nowrap;
    }}
    .tools-run-table td:nth-child(3) code {{
      display: block;
    }}
    code {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }}
    pre {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      border: 1px solid #ddd;
      padding: 8px;
      background: #fafafa;
    }}
  </style>
</head>
<body>
{body_html}
</body>
</html>"""


def export_from_markdown_file(
    md_path: Path,
    *,
    config: Optional[Dict[str, Any]] = None,
    export_html: Optional[bool] = None,
    export_pdf: Optional[bool] = None,
) -> ExportResult:
    """
    Optional export step:
      Markdown -> HTML (python-markdown)
      HTML -> PDF (WeasyPrint)

    If dependencies are missing, returns errors instead of raising.
    """
    md_path = Path(md_path)
    cfg = _report_exports_config(config)
    do_html = cfg["html"] if export_html is None else bool(export_html)
    do_pdf = cfg["pdf"] if export_pdf is None else bool(export_pdf)

    if not do_html and not do_pdf:
        return ExportResult()

    try:
        markdown_text = md_path.read_text(encoding="utf-8")
    except Exception as e:
        return ExportResult(html_error=f"Failed to read markdown: {e}", pdf_error=f"Failed to read markdown: {e}")

    out = ExportResult()

    html_text: Optional[str] = None
    if do_html or do_pdf:
        try:
            html_text = markdown_to_html(markdown_text)
        except Exception as e:
            msg = f"Markdown->HTML conversion failed: {e}"
            if do_html:
                out.html_error = msg
            if do_pdf:
                out.pdf_error = msg
            return out

    if do_html:
        try:
            html_path = md_path.with_suffix(".html")
            html_path.write_text(html_text or "", encoding="utf-8")
            out.html_path = html_path
        except Exception as e:
            out.html_error = f"Failed to write HTML: {e}"

    if do_pdf:
        try:
            weasy = _import_weasyprint()
            HTML = getattr(weasy, "HTML", None)
            if HTML is None:
                raise RuntimeError("weasyprint.HTML not available")
            CSS = getattr(weasy, "CSS", None)
            pdf_path = md_path.with_suffix(".pdf")
            # Slightly smaller base font size for PDF readability in long reports.
            pdf_styles = None
            if CSS is not None:
                pdf_styles = [
                    CSS(
                        string=(
                            "body { font-size: 11px; line-height: 1.35; } "
                            "code, pre { font-size: 10px; } "
                            "@page { margin: 14mm; }"
                        )
                    )
                ]
            HTML(string=html_text or "", base_url=str(md_path.parent)).write_pdf(
                str(pdf_path),
                stylesheets=pdf_styles,
            )
            out.pdf_path = pdf_path
        except Exception as e:
            out.pdf_error = f"Failed to write PDF: {e}"

    return out
