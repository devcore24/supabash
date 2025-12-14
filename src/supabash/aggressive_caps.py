from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


DEFAULT_AGGRESSIVE_CAPS: Dict[str, int] = {
    "max_nuclei_rate": 20,
    "default_nuclei_rate": 10,
    "max_gobuster_threads": 50,
    "max_parallel_workers": 6,
}


def _as_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def load_aggressive_caps(config: Dict[str, Any]) -> Dict[str, int]:
    core = config.get("core", {}) if isinstance(config, dict) else {}
    caps = core.get("aggressive_caps", {}) if isinstance(core, dict) else {}
    out = dict(DEFAULT_AGGRESSIVE_CAPS)
    if isinstance(caps, dict):
        for k in out.keys():
            if k in caps:
                out[k] = _as_int(caps.get(k), default=out[k])
    # sanitize
    out["max_nuclei_rate"] = max(1, out["max_nuclei_rate"])
    out["default_nuclei_rate"] = max(1, out["default_nuclei_rate"])
    out["max_gobuster_threads"] = max(1, out["max_gobuster_threads"])
    out["max_parallel_workers"] = max(1, out["max_parallel_workers"])
    return out


def apply_aggressive_caps(
    mode: str,
    *,
    config: Dict[str, Any],
    nuclei_rate_limit: int,
    gobuster_threads: int,
    max_workers: Optional[int] = None,
) -> Tuple[int, int, Optional[int], Dict[str, Any]]:
    """
    Enforces safety caps when mode == 'aggressive'. Returns adjusted values plus metadata.
    """
    meta: Dict[str, Any] = {"enabled": False, "caps": {}, "applied": []}
    if str(mode or "").strip().lower() != "aggressive":
        return nuclei_rate_limit, gobuster_threads, max_workers, meta

    caps = load_aggressive_caps(config)
    meta["enabled"] = True
    meta["caps"] = dict(caps)
    applied: List[str] = []

    nr = int(nuclei_rate_limit or 0)
    if nr <= 0:
        nr = caps["default_nuclei_rate"]
        applied.append(f"nuclei_rate_limit=0 -> default {nr}")
    if nr > caps["max_nuclei_rate"]:
        applied.append(f"nuclei_rate_limit {nr} -> {caps['max_nuclei_rate']}")
        nr = caps["max_nuclei_rate"]

    gt = int(gobuster_threads or 0)
    if gt <= 0:
        gt = 10
    if gt > caps["max_gobuster_threads"]:
        applied.append(f"gobuster_threads {gt} -> {caps['max_gobuster_threads']}")
        gt = caps["max_gobuster_threads"]

    mw = None if max_workers is None else int(max_workers)
    if mw is not None:
        if mw <= 0:
            mw = 1
        if mw > caps["max_parallel_workers"]:
            applied.append(f"max_workers {mw} -> {caps['max_parallel_workers']}")
            mw = caps["max_parallel_workers"]

    meta["applied"] = applied
    return nr, gt, mw, meta

