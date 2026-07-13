from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse
from supabash.report_schema import validate_report
from supabash.redaction import command_contains_unredacted_secret, find_sensitive_data_paths


REPORT_LINT_VERSION = 1
_SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
_URL_RE = re.compile(r"https?://[^\s<>\"'`]+", flags=re.IGNORECASE)
_EMBEDDED_AUTHORITY_RE = re.compile(
    r"/(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,}):\d{2,5}(?:/|$)",
    flags=re.IGNORECASE,
)


def _severity(value: Any) -> str:
    normalized = str(value or "INFO").strip().upper()
    return normalized if normalized in _SEVERITY_RANK else "INFO"


def _items(value: Any) -> List[Dict[str, Any]]:
    return [item for item in (value if isinstance(value, list) else []) if isinstance(item, dict)]


def _issue(
    code: str,
    severity: str,
    message: str,
    *,
    path: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "code": str(code),
        "severity": str(severity).strip().upper(),
        "message": str(message),
    }
    if path:
        item["path"] = path
    if isinstance(details, dict) and details:
        item["details"] = details
    return item


def _summary_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return []
    return _items(summary.get("findings"))


def _check_summary_consistency(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    detailed = _items(report.get("findings"))
    summary = _summary_findings(report)

    detail_critical = [item for item in detailed if _severity(item.get("severity")) == "CRITICAL"]
    summary_critical = [item for item in summary if _severity(item.get("severity")) == "CRITICAL"]
    if detail_critical and not summary_critical:
        issues.append(
            _issue(
                "critical_missing_from_summary",
                "ERROR",
                "Detailed findings contain CRITICAL evidence, but the summary contains no CRITICAL finding.",
                path="summary.findings",
                details={"detailed_critical_count": len(detail_critical)},
            )
        )
    if summary_critical and not detail_critical:
        issues.append(
            _issue(
                "summary_critical_without_detail",
                "ERROR",
                "The summary contains a CRITICAL finding that is not supported by detailed findings.",
                path="summary.findings",
                details={"summary_critical_count": len(summary_critical)},
            )
        )

    detail_high_risk = [
        item for item in detailed if _SEVERITY_RANK.get(_severity(item.get("severity")), 0) >= 4
    ]
    summary_high_risk = [
        item for item in summary if _SEVERITY_RANK.get(_severity(item.get("severity")), 0) >= 4
    ]
    if detail_high_risk and not summary_high_risk:
        issues.append(
            _issue(
                "high_risk_missing_from_summary",
                "WARNING",
                "Detailed findings contain HIGH/CRITICAL evidence, but the summary has no high-risk finding.",
                path="summary.findings",
                details={"detailed_high_risk_count": len(detail_high_risk)},
            )
        )
    return issues


def _iter_url_fields(report: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    collections: Sequence[Tuple[str, Any]] = (
        ("findings", report.get("findings")),
        ("summary.findings", _summary_findings(report)),
        ("finding_clusters", report.get("finding_clusters")),
        ("unresolved_high_risk_clusters", report.get("unresolved_high_risk_clusters")),
    )
    interesting = {
        "evidence",
        "target",
        "url",
        "endpoint",
        "path",
        "targets",
        "urls",
        "evidence_samples",
    }
    for prefix, raw_items in collections:
        for index, item in enumerate(_items(raw_items)):
            for key in interesting:
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    yield f"{prefix}[{index}].{key}", value.strip()
                elif isinstance(value, list):
                    for value_index, part in enumerate(value):
                        if isinstance(part, str) and part.strip():
                            yield f"{prefix}[{index}].{key}[{value_index}]", part.strip()


def _url_problem(candidate: str) -> Optional[str]:
    raw = str(candidate or "").strip()
    cleaned = raw.rstrip(".,;:!?)]}")
    try:
        parsed = urlparse(cleaned)
    except Exception:
        return "URL could not be parsed"
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        return "URL is missing a valid HTTP(S) authority"
    if any(ch.isspace() for ch in parsed.netloc):
        return "URL authority contains whitespace"
    if _EMBEDDED_AUTHORITY_RE.search(parsed.path or ""):
        return "URL path contains an embedded host:port authority"
    if re.search(r"https?://", parsed.path or "", flags=re.IGNORECASE):
        return "URL path contains a second URL scheme"
    try:
        port = parsed.port
        if port is not None and not (1 <= int(port) <= 65535):
            return "URL port is outside the valid range"
    except ValueError:
        return "URL contains an invalid port"
    return None


def _check_url_hygiene(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for path, text in _iter_url_fields(report):
        candidates = _URL_RE.findall(text)
        if not candidates and text.lower().startswith(("http://", "https://")):
            candidates = [text]
        for candidate in candidates:
            problem = _url_problem(candidate)
            if not problem:
                continue
            key = (path, candidate)
            if key in seen:
                continue
            seen.add(key)
            issues.append(
                _issue(
                    "malformed_url",
                    "ERROR",
                    problem,
                    path=path,
                    details={"value": candidate[:500]},
                )
            )
    return issues


def _check_cluster_state(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    clusters = _items(report.get("finding_clusters"))
    unresolved = _items(report.get("unresolved_high_risk_clusters"))
    if not clusters and not unresolved:
        return issues

    by_id: Dict[str, Dict[str, Any]] = {}
    for index, cluster in enumerate(clusters):
        cluster_id = str(cluster.get("cluster_id") or "").strip()
        if not cluster_id:
            issues.append(
                _issue(
                    "cluster_missing_id",
                    "ERROR",
                    "Finding cluster is missing cluster_id.",
                    path=f"finding_clusters[{index}].cluster_id",
                )
            )
            continue
        if cluster_id in by_id:
            issues.append(
                _issue(
                    "duplicate_cluster_id",
                    "ERROR",
                    "Multiple finding clusters use the same cluster_id.",
                    path=f"finding_clusters[{index}].cluster_id",
                    details={"cluster_id": cluster_id},
                )
            )
        by_id[cluster_id] = cluster

    for index, item in enumerate(unresolved):
        cluster_id = str(item.get("cluster_id") or "").strip()
        source = by_id.get(cluster_id)
        if not cluster_id or source is None:
            issues.append(
                _issue(
                    "unresolved_cluster_reference_missing",
                    "ERROR",
                    "Unresolved high-risk cluster does not reference a known finding cluster.",
                    path=f"unresolved_high_risk_clusters[{index}].cluster_id",
                    details={"cluster_id": cluster_id},
                )
            )
            continue
        if bool(source.get("seen_in_agentic")):
            issues.append(
                _issue(
                    "covered_cluster_marked_unresolved",
                    "ERROR",
                    "A cluster marked as covered by agentic evidence is also listed as unresolved.",
                    path=f"unresolved_high_risk_clusters[{index}]",
                    details={"cluster_id": cluster_id},
                )
            )
        if _SEVERITY_RANK.get(_severity(source.get("severity")), 0) < 4:
            issues.append(
                _issue(
                    "non_high_risk_cluster_marked_unresolved",
                    "WARNING",
                    "An unresolved high-risk entry points to a cluster below HIGH severity.",
                    path=f"unresolved_high_risk_clusters[{index}]",
                    details={"cluster_id": cluster_id, "severity": source.get("severity")},
                )
            )

    overview = report.get("finding_cluster_overview")
    if isinstance(overview, dict):
        expected_open = len(unresolved)
        try:
            recorded_open = int(overview.get("open_high_risk_cluster_count", 0))
        except Exception:
            recorded_open = -1
        if recorded_open != expected_open:
            issues.append(
                _issue(
                    "cluster_overview_count_mismatch",
                    "ERROR",
                    "Finding-cluster overview does not match the unresolved cluster list.",
                    path="finding_cluster_overview.open_high_risk_cluster_count",
                    details={"recorded": recorded_open, "actual": expected_open},
                )
            )
    return issues


def _check_likely_noise(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    for index, item in enumerate(_items(report.get("findings"))):
        finding_type = str(item.get("type") or item.get("category") or "").strip().lower()
        title = str(item.get("title") or "").strip().lower()
        discovery_like = "discover" in finding_type or "discover" in title or finding_type in {"browser_url", "url"}
        if not discovery_like:
            continue
        status = item.get("status_code", item.get("http_status", item.get("response_status")))
        try:
            status_code = int(status)
        except (TypeError, ValueError):
            evidence = str(item.get("evidence") or "")
            match = re.search(r"(?:HTTP\s+|status(?:_code)?[=: ]+)(404|501)\b", evidence, flags=re.IGNORECASE)
            status_code = int(match.group(1)) if match else 0
        if status_code not in {404, 501}:
            continue
        issues.append(
            _issue(
                "likely_noise_discovery",
                "WARNING",
                f"Discovery-only finding is backed by HTTP {status_code}, which is likely scanner seed-path noise.",
                path=f"findings[{index}]",
                details={"status_code": status_code},
            )
        )
    return issues


def _check_command_secrets(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []

    def visit(value: Any, path: str, *, command_context: bool = False) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized_key = re.sub(r"[^a-z0-9]", "", str(key or "").lower())
                visit(
                    child,
                    f"{path}.{key}" if path else str(key),
                    command_context=(
                        command_context or normalized_key in {"command", "commands"}
                    ),
                )
            return
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]", command_context=command_context)
            return
        if command_context and isinstance(value, str) and command_contains_unredacted_secret(value):
            issues.append(
                _issue(
                    "credential_in_command_trace",
                    "ERROR",
                    "Command trace contains an unredacted credential-bearing argument.",
                    path=path,
                )
            )

    visit(report, "")
    return issues


def _check_persisted_secrets(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    for path in find_sensitive_data_paths(report):
        issues.append(
            _issue(
                "credential_in_persisted_data",
                "ERROR",
                "Report contains unredacted credential material outside command traces.",
                path=path,
            )
        )
    return issues


def _artifact_references(item: Dict[str, Any]) -> List[str]:
    refs: List[str] = []
    for key in ("evidence_artifact", "artifact", "evidence_reference"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            refs.append(value.strip())
    for key in ("evidence_artifacts", "artifacts", "evidence_references"):
        value = item.get(key)
        if isinstance(value, list):
            refs.extend(str(part).strip() for part in value if isinstance(part, str) and part.strip())
    return refs


def _check_evidence_references(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    evidence_pack = report.get("evidence_pack")
    if not isinstance(evidence_pack, dict):
        return issues
    artifacts = _items(evidence_pack.get("artifacts"))
    known_paths = {str(item.get("path") or "").strip() for item in artifacts if str(item.get("path") or "").strip()}
    for prefix, values in (("findings", report.get("findings")), ("summary.findings", _summary_findings(report))):
        for index, item in enumerate(_items(values)):
            for ref in _artifact_references(item):
                if ref not in known_paths:
                    issues.append(
                        _issue(
                            "broken_evidence_reference",
                            "ERROR",
                            "Finding references an artifact that is not present in the evidence-pack index.",
                            path=f"{prefix}[{index}]",
                            details={"reference": ref},
                        )
                    )
    return issues


def lint_report(report: Any) -> Dict[str, Any]:
    """Run deterministic report-quality checks without mutating the report."""
    if not isinstance(report, dict):
        issues = [_issue("report_not_object", "ERROR", "Report must be a JSON object.")]
    else:
        issues = []
        schema_ok, schema_errors = validate_report(report, kind="audit")
        if not schema_ok:
            for error in schema_errors[:50]:
                issues.append(
                    _issue(
                        "schema_validation_error",
                        "ERROR",
                        str(error),
                        path="schema",
                    )
                )
        issues.extend(_check_summary_consistency(report))
        issues.extend(_check_url_hygiene(report))
        issues.extend(_check_cluster_state(report))
        issues.extend(_check_likely_noise(report))
        issues.extend(_check_command_secrets(report))
        issues.extend(_check_persisted_secrets(report))
        issues.extend(_check_evidence_references(report))

    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for item in issues:
        severity = str(item.get("severity") or "INFO").upper()
        counts[severity if severity in counts else "INFO"] += 1
    return {
        "version": REPORT_LINT_VERSION,
        "valid": counts["ERROR"] == 0,
        "issue_count": len(issues),
        "counts": counts,
        "issues": issues,
    }


def render_report_lint_markdown(lint_result: Dict[str, Any], *, report_file: str = "") -> str:
    counts = lint_result.get("counts") if isinstance(lint_result.get("counts"), dict) else {}
    lines = ["# Supabash Report Lint", ""]
    if report_file:
        lines.append(f"- report: `{report_file}`")
    lines.extend(
        [
            f"- valid: `{str(bool(lint_result.get('valid'))).lower()}`",
            f"- errors: {int(counts.get('ERROR', 0) or 0)}",
            f"- warnings: {int(counts.get('WARNING', 0) or 0)}",
            f"- info: {int(counts.get('INFO', 0) or 0)}",
            "",
            "## Issues",
            "",
        ]
    )
    issues = _items(lint_result.get("issues"))
    if not issues:
        lines.append("No deterministic report-quality issues detected.")
    else:
        for item in issues:
            severity = str(item.get("severity") or "INFO").upper()
            code = str(item.get("code") or "unknown")
            message = str(item.get("message") or "")
            path = str(item.get("path") or "").strip()
            suffix = f" (`{path}`)" if path else ""
            lines.append(f"- **{severity}** `{code}`: {message}{suffix}")
    return "\n".join(lines).rstrip() + "\n"


def _report_provenance(
    report: Dict[str, Any],
    output: Path,
    *,
    provenance_mode: str = "auto",
) -> Dict[str, Any]:
    mode = str(provenance_mode or "auto").strip().lower()
    if mode not in {"auto", "pre_lint_report_object"}:
        raise ValueError(f"Unsupported report lint provenance mode: {provenance_mode}")

    if mode == "auto" and output.is_file():
        payload = output.read_bytes()
        hash_scope = "source_file"
    else:
        snapshot = {
            key: value
            for key, value in report.items()
            if key not in {"report_lint", "report_lint_artifacts"}
        }
        payload = json.dumps(snapshot, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        hash_scope = "pre_lint_report_object"
    return {
        "report_file": output.name,
        "schema_version": report.get("schema_version"),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "hash_scope": hash_scope,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_text(content, encoding="utf-8")
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def write_report_lint_artifacts(
    report: Dict[str, Any],
    output: Optional[Path],
    *,
    provenance_mode: str = "auto",
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Attach lint results and optionally atomically write JSON/Markdown sidecars.

    ``auto`` hashes an existing source report, which is appropriate for the
    standalone lint CLI. Audit persistence uses ``pre_lint_report_object`` so
    overwriting an existing output path cannot attribute the previous file's
    hash to the new in-memory report.
    """
    lint_result = lint_report(report)
    report["report_lint"] = lint_result
    if output is None:
        return lint_result, None

    output = Path(output)
    lint_result["source"] = _report_provenance(
        report,
        output,
        provenance_mode=provenance_mode,
    )
    json_path = output.parent / f"{output.stem}-lint.json"
    markdown_path = output.parent / f"{output.stem}-lint.md"
    metadata = {
        "json_file": json_path.name,
        "markdown_file": markdown_path.name,
        "version": REPORT_LINT_VERSION,
        "source_sha256": lint_result["source"]["sha256"],
        "source_hash_scope": lint_result["source"]["hash_scope"],
    }
    report["report_lint_artifacts"] = metadata

    _atomic_write_text(json_path, json.dumps(lint_result, indent=2))
    _atomic_write_text(
        markdown_path,
        render_report_lint_markdown(lint_result, report_file=output.name),
    )
    return lint_result, metadata
