from __future__ import annotations

import os
import uuid
from pathlib import Path


def artifacts_dir() -> Path:
    root = Path(__file__).resolve().parents[1]
    base = os.environ.get("SUPABASH_TEST_REPORT_DIR")
    d = Path(base) if base else (root / "reports" / "tests")
    d.mkdir(parents=True, exist_ok=True)
    return d


def artifact_path(name: str) -> Path:
    """
    Returns a unique path under reports/ for test outputs.
    """
    safe = "".join(ch for ch in str(name) if ch.isalnum() or ch in ("-", "_", ".", "/")).strip()
    safe = safe.replace("/", "-")
    if not safe:
        safe = "artifact"
    suffix = uuid.uuid4().hex[:8]
    return artifacts_dir() / f"{safe}-{suffix}"


def cleanup_artifact(path: Path) -> None:
    """
    Default: remove artifacts so tests are repeatable.
    Set SUPABASH_KEEP_TEST_REPORTS=1 to keep them for inspection.
    """
    keep = os.environ.get("SUPABASH_KEEP_TEST_REPORTS", "").strip().lower() in {"1", "true", "yes"}
    if keep:
        return
    try:
        path.unlink(missing_ok=True)  # py3.11+
    except Exception:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass

