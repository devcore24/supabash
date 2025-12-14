from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = "1.0"


def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _as_str(x: Any) -> Optional[str]:
    if x is None:
        return None
    if isinstance(x, str):
        s = x.strip()
        return s or None
    return str(x).strip() or None


def _validate_result_entry(entry: Any, idx: int) -> List[str]:
    errors: List[str] = []
    if not isinstance(entry, dict):
        return [f"results[{idx}] must be an object"]

    tool = _as_str(entry.get("tool"))
    if not tool:
        errors.append(f"results[{idx}].tool is required")

    skipped = entry.get("skipped")
    success = entry.get("success")

    if skipped is None:
        skipped = False
    if not isinstance(skipped, bool):
        errors.append(f"results[{idx}].skipped must be boolean when present")
        skipped = False

    if success is None:
        # allow missing success only when skipped=True
        if not skipped:
            errors.append(f"results[{idx}].success is required when not skipped")
    elif not isinstance(success, bool):
        errors.append(f"results[{idx}].success must be boolean")

    if skipped:
        reason = entry.get("reason")
        if reason is not None and not isinstance(reason, str):
            errors.append(f"results[{idx}].reason must be string when present")

    if skipped is False and success is False:
        err = entry.get("error")
        if err is not None and not isinstance(err, str):
            errors.append(f"results[{idx}].error must be string when present")

    cmd = entry.get("command")
    if cmd is not None and not isinstance(cmd, str):
        errors.append(f"results[{idx}].command must be string when present")

    return errors


def validate_report(report: Any, *, kind: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Best-effort validation for Supabash report JSON. Returns (is_valid, errors).

    This is intentionally permissive: it checks for core structure and types,
    while allowing the tool-specific payloads to vary.
    """
    errors: List[str] = []
    if not isinstance(report, dict):
        return False, ["report must be an object"]

    schema_version = report.get("schema_version")
    if schema_version is None:
        errors.append("schema_version is required")
    elif not isinstance(schema_version, str):
        errors.append("schema_version must be a string")

    target = _as_str(report.get("target"))
    if not target:
        errors.append("target is required")

    results = report.get("results")
    if results is None:
        errors.append("results is required")
        results = []
    if not isinstance(results, list):
        errors.append("results must be a list")
        results = []

    for i, entry in enumerate(results):
        errors.extend(_validate_result_entry(entry, i))

    started_at = report.get("started_at")
    if started_at is not None and not _is_number(started_at):
        errors.append("started_at must be numeric when present")

    finished_at = report.get("finished_at")
    if finished_at is not None and not _is_number(finished_at):
        errors.append("finished_at must be numeric when present")

    if kind:
        k = str(kind).strip().lower()
        if k == "react":
            react = report.get("react")
            if react is None or not isinstance(react, dict):
                errors.append("react is required for react reports")
        elif k == "audit":
            # no extra strict requirements today
            pass

    return len(errors) == 0, errors


def annotate_schema_validation(report: Dict[str, Any], *, kind: Optional[str] = None) -> Dict[str, Any]:
    ok, errs = validate_report(report, kind=kind)
    report["schema_validation"] = {"valid": bool(ok), "errors": errs[:50]}
    return report

