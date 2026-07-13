from __future__ import annotations

import os
import shutil
from datetime import datetime
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
    base = safe
    ext = ""
    if "." in safe:
        base, ext = safe.rsplit(".", 1)
        ext = f".{ext}"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = artifacts_dir() / f"{base}-{stamp}{ext}"
    if not candidate.exists():
        return candidate
    counter = 1
    while True:
        candidate = artifacts_dir() / f"{base}-{stamp}-{counter}{ext}"
        if not candidate.exists():
            return candidate
        counter += 1


def cleanup_artifact(path: Path) -> None:
    """Remove a generated report bundle when SUPABASH_KEEP_TEST_REPORTS=0."""
    keep_env = os.environ.get("SUPABASH_KEEP_TEST_REPORTS", "").strip().lower()
    if keep_env in {"", "1", "true", "yes"}:
        return

    try:
        base = artifacts_dir().resolve()
        candidate = Path(path).resolve()
        candidate.relative_to(base)
    except Exception:
        return

    targets = [candidate]
    targets.extend(item for item in candidate.parent.glob(f"{candidate.stem}-*") if item.is_file())
    evidence_candidates = [
        candidate.parent / "evidence" / candidate.stem,
        candidate.parent / "evidence" if candidate.parent.name == candidate.stem else None,
    ]
    for target in targets:
        try:
            target.unlink(missing_ok=True)
        except Exception:
            pass
    for directory in evidence_candidates:
        if directory is None:
            continue
        try:
            resolved = directory.resolve()
            resolved.relative_to(base)
            if resolved.is_dir():
                shutil.rmtree(resolved)
        except Exception:
            pass
