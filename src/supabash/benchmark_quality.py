from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from supabash.report_lint import lint_report
from supabash.finding_identity import classify_finding_risk_class, finding_dedup_key


DEFAULT_THRESHOLDS: Dict[str, Any] = {
    "max_lint_errors": 0,
    "max_duplicate_rate": 0.35,
    "max_agentic_actions": 10,
    "min_high_risk_findings": 0,
}

PROFILE_THRESHOLDS: Dict[str, Dict[str, Any]] = {
    "compliance_soc2": {"max_duplicate_rate": 0.25, "max_agentic_actions": 10},
    "soc2": {"max_duplicate_rate": 0.25, "max_agentic_actions": 10},
    "compliance_pci": {"max_duplicate_rate": 0.20, "max_agentic_actions": 10},
    "pci": {"max_duplicate_rate": 0.20, "max_agentic_actions": 10},
}

_INTEGER_THRESHOLDS = {
    "max_lint_errors",
    "max_agentic_actions",
    "min_high_risk_findings",
    "max_open_high_risk_clusters",
    "max_high_risk_findings",
}
_FLOAT_THRESHOLDS = {"max_duplicate_rate", "max_duration_seconds"}
_LIST_THRESHOLDS = {
    "required_risk_classes",
    "forbidden_risk_classes",
    "required_title_contains",
    "forbidden_title_contains",
}
_SUPPORTED_THRESHOLDS = _INTEGER_THRESHOLDS | _FLOAT_THRESHOLDS | _LIST_THRESHOLDS


def _as_int(value: Any, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _as_float(value: Any, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a non-negative number")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{name} must be a non-negative number")
    if name == "max_duplicate_rate" and parsed > 1:
        raise ValueError("max_duplicate_rate must be between 0 and 1")
    return parsed


def _string_list(value: Any, *, name: str) -> List[str]:
    if not isinstance(value, (list, tuple, set)) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a list of non-empty strings")
    normalized: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{name} must be a list of non-empty strings")
        token = item.strip().lower()
        if token not in normalized:
            normalized.append(token)
    return normalized


def validate_expectations(expectations: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate and normalize a benchmark expectations mapping."""
    if expectations is None:
        return {}
    if not isinstance(expectations, dict):
        raise ValueError("expectations must be a JSON object")
    unknown = sorted(str(key) for key in expectations if str(key) not in _SUPPORTED_THRESHOLDS)
    if unknown:
        raise ValueError(f"unsupported expectation keys: {', '.join(unknown)}")

    normalized: Dict[str, Any] = {}
    for name, value in expectations.items():
        if name in _INTEGER_THRESHOLDS:
            normalized[name] = _as_int(value, name=name)
        elif name in _FLOAT_THRESHOLDS:
            normalized[name] = _as_float(value, name=name)
        elif name in _LIST_THRESHOLDS:
            normalized[name] = _string_list(value, name=name)
    return normalized


def _findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = report.get("findings")
    return [item for item in (raw if isinstance(raw, list) else []) if isinstance(item, dict)]


def _normalized_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _duplicate_metrics(findings: Sequence[Dict[str, Any]]) -> Tuple[int, int, float]:
    total = len(findings)
    unique = len({finding_dedup_key(item) for item in findings})
    duplicates = max(0, total - unique)
    rate = float(duplicates / total) if total else 0.0
    return unique, duplicates, rate


def _duration_seconds(report: Dict[str, Any]) -> Optional[float]:
    started_raw = report.get("started_at")
    finished_raw = report.get("finished_at")
    if started_raw is not None or finished_raw is not None:
        try:
            started_at = float(started_raw)
            finished_at = float(finished_raw)
        except (TypeError, ValueError):
            return None
        if (
            not math.isfinite(started_at)
            or not math.isfinite(finished_at)
            or finished_at < started_at
        ):
            return None
        return finished_at - started_at

    evidence_pack = report.get("evidence_pack") if isinstance(report.get("evidence_pack"), dict) else {}
    runtime = evidence_pack.get("runtime") if isinstance(evidence_pack.get("runtime"), dict) else {}
    try:
        duration = float(runtime.get("duration_seconds"))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(duration) or duration < 0:
        return None
    return duration


def _thresholds(report: Dict[str, Any], expectations: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(DEFAULT_THRESHOLDS)
    profile = str(report.get("compliance_profile") or "").strip().lower()
    if profile in PROFILE_THRESHOLDS:
        merged.update(PROFILE_THRESHOLDS[profile])
    merged.update(validate_expectations(expectations))
    return merged


def _check(name: str, passed: bool, actual: Any, expected: Any, message: str) -> Dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "actual": actual,
        "expected": expected,
        "message": message,
    }


def evaluate_report_quality(
    report: Any,
    expectations: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Recompute deterministic quality signals and evaluate benchmark gates."""
    if not isinstance(report, dict):
        return {
            "version": 1,
            "passed": False,
            "checks": [
                _check("report_object", False, type(report).__name__, "dict", "Report must be a JSON object.")
            ],
            "metrics": {},
            "report_lint": lint_report(report),
        }

    thresholds = _thresholds(report, expectations)
    findings = _findings(report)
    high_risk = [
        item
        for item in findings
        if str(item.get("severity") or "INFO").strip().upper() in {"CRITICAL", "HIGH"}
    ]
    risk_classes = {
        _normalized_text(classify_finding_risk_class(item))
        for item in findings
    }
    titles = [_normalized_text(item.get("title")) for item in findings]

    lint_result = lint_report(report)
    lint_counts = lint_result.get("counts") if isinstance(lint_result.get("counts"), dict) else {}
    lint_errors = int(lint_counts.get("ERROR", 0) or 0)
    unique_findings, duplicate_findings, duplicate_rate = _duplicate_metrics(findings)

    ai_audit = report.get("ai_audit") if isinstance(report.get("ai_audit"), dict) else {}
    raw_actions = ai_audit.get("actions", [])
    actions_container_valid = isinstance(raw_actions, list)
    actions = raw_actions if actions_container_valid else []
    action_count = len([item for item in actions if isinstance(item, dict)])
    malformed_action_count = len(actions) - action_count if actions_container_valid else 1
    unresolved = report.get("unresolved_high_risk_clusters")
    open_high_risk = len([item for item in unresolved if isinstance(item, dict)]) if isinstance(unresolved, list) else 0
    duration_seconds = _duration_seconds(report)

    checks: List[Dict[str, Any]] = []
    max_lint_errors = int(thresholds["max_lint_errors"])
    checks.append(
        _check(
            "lint_errors",
            lint_errors <= max_lint_errors,
            lint_errors,
            f"<= {max_lint_errors}",
            "Recomputed deterministic report lint must stay within the error budget.",
        )
    )

    max_duplicate_rate = float(thresholds["max_duplicate_rate"])
    checks.append(
        _check(
            "duplicate_rate",
            duplicate_rate <= max_duplicate_rate,
            duplicate_rate,
            f"<= {max_duplicate_rate}",
            "Recomputed finding duplication must stay below the benchmark threshold.",
        )
    )

    checks.append(
        _check(
            "agentic_actions_valid",
            actions_container_valid and malformed_action_count == 0,
            malformed_action_count,
            0,
            "Every agentic action record must be a JSON object.",
        )
    )

    max_actions = int(thresholds["max_agentic_actions"])
    checks.append(
        _check(
            "agentic_actions",
            action_count <= max_actions,
            action_count,
            f"<= {max_actions}",
            "Agentic action count must remain bounded.",
        )
    )

    min_high_risk = int(thresholds["min_high_risk_findings"])
    checks.append(
        _check(
            "high_risk_yield",
            len(high_risk) >= min_high_risk,
            len(high_risk),
            f">= {min_high_risk}",
            "Benchmark reports must retain the expected CRITICAL/HIGH yield.",
        )
    )

    if "max_open_high_risk_clusters" in thresholds:
        max_open = int(thresholds["max_open_high_risk_clusters"])
        checks.append(
            _check(
                "open_high_risk_clusters",
                open_high_risk <= max_open,
                open_high_risk,
                f"<= {max_open}",
                "Coverage-debt clusters must stay within the scenario budget.",
            )
        )

    if "max_duration_seconds" in thresholds:
        max_duration = float(thresholds["max_duration_seconds"])
        checks.append(
            _check(
                "duration_seconds",
                duration_seconds is not None and duration_seconds <= max_duration,
                duration_seconds,
                f"<= {max_duration}",
                "Benchmark runtime must be measured and stay within the scenario budget.",
            )
        )

    if "max_high_risk_findings" in thresholds:
        max_high_risk = int(thresholds["max_high_risk_findings"])
        checks.append(
            _check(
                "max_high_risk_findings",
                len(high_risk) <= max_high_risk,
                len(high_risk),
                f"<= {max_high_risk}",
                "Protected scenarios must stay within the false-positive high-risk budget.",
            )
        )

    for risk_class in thresholds.get("required_risk_classes", []):
        checks.append(
            _check(
                f"risk_class:{risk_class}",
                risk_class in risk_classes,
                risk_class in risk_classes,
                True,
                f"Expected risk class {risk_class!r} must be present.",
            )
        )
    for risk_class in thresholds.get("forbidden_risk_classes", []):
        present = risk_class in risk_classes
        checks.append(
            _check(
                f"forbidden_risk_class:{risk_class}",
                not present,
                present,
                False,
                f"Risk class {risk_class!r} must not be present.",
            )
        )
    for fragment in thresholds.get("required_title_contains", []):
        present = any(fragment in title for title in titles)
        checks.append(
            _check(
                f"title_contains:{fragment}",
                present,
                present,
                True,
                f"At least one finding title must contain {fragment!r}.",
            )
        )
    for fragment in thresholds.get("forbidden_title_contains", []):
        present = any(fragment in title for title in titles)
        checks.append(
            _check(
                f"forbidden_title_contains:{fragment}",
                not present,
                present,
                False,
                f"No finding title may contain {fragment!r}.",
            )
        )

    return {
        "version": 1,
        "passed": all(bool(item.get("passed")) for item in checks),
        "profile": str(report.get("compliance_profile") or "").strip() or None,
        "thresholds": thresholds,
        "metrics": {
            "lint_errors": lint_errors,
            "total_findings": len(findings),
            "unique_findings": unique_findings,
            "duplicate_findings": duplicate_findings,
            "duplicate_rate": duplicate_rate,
            "agentic_actions": action_count,
            "malformed_agentic_actions": malformed_action_count,
            "high_risk_findings": len(high_risk),
            "open_high_risk_clusters": open_high_risk,
            "duration_seconds": duration_seconds,
            "risk_classes": sorted(risk_classes),
        },
        "checks": checks,
        "report_lint": lint_result,
    }
