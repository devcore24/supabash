from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from supabash.report import (
    build_compliance_coverage_matrix,
    build_recommended_next_actions,
    normalize_report_summary,
)


FindingMetricsBuilder = Callable[[List[Dict[str, Any]]], Dict[str, Any]]


def finalize_report_content(
    report: Dict[str, Any],
    findings: List[Dict[str, Any]],
    compliance_profile: Optional[str],
    *,
    finding_metrics_builder: Optional[FindingMetricsBuilder] = None,
    finished_at: Optional[float] = None,
) -> Dict[str, Any]:
    """Apply shared deterministic post-processing to audit and AI-audit reports."""
    normalized_findings = [item for item in (findings or []) if isinstance(item, dict)]
    report["findings"] = normalized_findings
    had_structured_summary = isinstance(report.get("summary"), dict)
    llm_calls = report.get("llm", {}).get("calls") if isinstance(report.get("llm"), dict) else []
    llm_summary_error = any(
        isinstance(call, dict) and str(call.get("error") or "").strip()
        for call in (llm_calls if isinstance(llm_calls, list) else [])
    )

    normalized_summary, summary_meta = normalize_report_summary(
        report.get("summary"),
        normalized_findings,
        finding_clusters=report.get("finding_clusters")
        if isinstance(report.get("finding_clusters"), list)
        else None,
    )
    if isinstance(normalized_summary, dict):
        report["summary"] = normalized_summary
        if llm_summary_error and not had_structured_summary:
            fallback_note = "Deterministic summary fallback used because the LLM summary was unavailable or invalid."
            notes = report.setdefault("summary_notes", [])
            if isinstance(notes, list) and fallback_note not in notes:
                notes.append(fallback_note)
    if isinstance(summary_meta, dict) and summary_meta:
        report["summary_normalization"] = summary_meta
    else:
        report.pop("summary_normalization", None)

    if callable(finding_metrics_builder):
        try:
            report["finding_metrics"] = finding_metrics_builder(normalized_findings)
        except Exception:
            pass

    summary_findings: List[Dict[str, Any]] = []
    summary = report.get("summary")
    if isinstance(summary, dict):
        summary_findings = [
            item for item in (summary.get("findings") or []) if isinstance(item, dict)
        ]
    try:
        report["recommended_next_actions"] = build_recommended_next_actions(
            summary_findings,
            normalized_findings,
            compliance_profile,
        )
    except Exception:
        pass

    if isinstance(compliance_profile, str) and compliance_profile.strip():
        try:
            report["compliance_coverage_matrix"] = build_compliance_coverage_matrix(report)
        except Exception:
            pass

    report["finished_at"] = float(finished_at if finished_at is not None else time.time())
    return report


def attach_evidence_artifact_references(report: Dict[str, Any]) -> None:
    """Attach concrete evidence-pack paths to findings by producing tool."""
    evidence_pack = report.get("evidence_pack")
    if not isinstance(evidence_pack, dict):
        return
    by_tool: Dict[str, List[str]] = {}
    for artifact in evidence_pack.get("artifacts") or []:
        if not isinstance(artifact, dict) or str(artifact.get("status") or "").lower() != "success":
            continue
        tool = str(artifact.get("tool") or "").strip().lower()
        path = str(artifact.get("path") or "").strip()
        if tool and path and path not in by_tool.setdefault(tool, []):
            by_tool[tool].append(path)

    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        tools: List[str] = []
        primary = str(finding.get("tool") or "").strip().lower()
        if primary:
            tools.append(primary)
        for tool in finding.get("corroborating_tools") or []:
            normalized = str(tool or "").strip().lower()
            if normalized and normalized not in tools:
                tools.append(normalized)
        refs: List[str] = []
        for tool in tools:
            for path in by_tool.get(tool, [])[:2]:
                if path not in refs:
                    refs.append(path)
        if refs:
            finding["evidence_artifacts"] = refs[:6]


def atomic_write_report_json(report: Dict[str, Any], output: Path) -> None:
    """Atomically replace the main JSON report after complete serialization."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        os.replace(temp_path, output)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass
