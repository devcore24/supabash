from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Union


PathLike = Union[str, Path]


def build_report_paths(
    output: Optional[PathLike],
    markdown: Optional[PathLike] = None,
    *,
    now: Optional[datetime] = None,
    default_dir: PathLike = "reports",
    default_basename: str = "report",
) -> Tuple[Path, Path]:
    """
    Resolve report output paths (JSON + Markdown).

    - If output is None: defaults to reports/report-YYYYmmdd-HHMMSS/report-YYYYmmdd-HHMMSS.json
    - If output is a directory that exists: writes report-<ts>.json inside it
    - If output has no suffix: appends .json
    - If markdown is None: defaults to <output>.md
    - If markdown is a directory that exists: writes <output-stem>.md inside it
    - If markdown has no suffix: appends .md
    """
    now = now or datetime.now()
    ts = now.strftime("%Y%m%d-%H%M%S")

    base = (default_basename or "report").strip() or "report"
    run_slug = f"{base}-{ts}"
    out_path = Path(output) if output else Path(default_dir) / run_slug / f"{run_slug}.json"
    if out_path.exists() and out_path.is_dir():
        out_path = out_path / f"{base}-{ts}.json"
    elif out_path.suffix == "":
        out_path = out_path.with_suffix(".json")

    md_path = Path(markdown) if markdown else out_path.with_suffix(".md")
    if md_path.exists() and md_path.is_dir():
        md_path = md_path / f"{out_path.stem}.md"
    elif md_path.suffix == "":
        md_path = md_path.with_suffix(".md")

    return out_path, md_path
