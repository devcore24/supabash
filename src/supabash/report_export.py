from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


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


def markdown_to_html(markdown_text: str) -> str:
    md = _import_markdown()
    fn = getattr(md, "markdown", None)
    if not callable(fn):
        raise RuntimeError("markdown module does not provide markdown()")
    # Enable heading IDs so in-document anchors (e.g. #summary) work in the exported HTML/PDF.
    # - toc: generates stable id="" attributes for headings
    # - attr_list: allows explicit heading IDs like "## Summary {#summary}" if we ever want them
    return fn(markdown_text, extensions=["tables", "fenced_code", "toc", "attr_list"], output_format="html5")


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
            pdf_path = md_path.with_suffix(".pdf")
            HTML(string=html_text or "", base_url=str(md_path.parent)).write_pdf(str(pdf_path))
            out.pdf_path = pdf_path
        except Exception as e:
            out.pdf_error = f"Failed to write PDF: {e}"

    return out
