from __future__ import annotations

import hashlib
import json
import re
import zlib
from pathlib import Path
from typing import Any

from supabash.redaction import find_sensitive_data_paths
from supabash.report_lint import lint_report


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_REPORTS_ROOT = REPOSITORY_ROOT / "example_reports"
AUDIT_REPORT_KEYS = {"schema_version", "target", "findings", "results"}
INDEPENDENT_SECRET_PATTERNS = {
    "openai": re.compile(rb"(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}"),
    "github": re.compile(rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "aws": re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "google": re.compile(rb"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{30,}"),
    "slack": re.compile(rb"(?<![A-Za-z0-9-])xox[a-z]-[A-Za-z0-9-]{10,}"),
    "stripe": re.compile(rb"(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _example_json_files() -> list[Path]:
    return sorted(EXAMPLE_REPORTS_ROOT.rglob("*.json"))


def _example_audit_reports() -> list[tuple[Path, dict[str, Any]]]:
    reports: list[tuple[Path, dict[str, Any]]] = []
    for path in _example_json_files():
        payload = _load_json(path)
        if isinstance(payload, dict) and AUDIT_REPORT_KEYS.issubset(payload):
            reports.append((path, payload))
    return reports


def _relative(path: Path) -> str:
    return str(path.relative_to(REPOSITORY_ROOT))


def test_example_audit_reports_pass_report_lint() -> None:
    reports = _example_audit_reports()
    assert reports, "No example audit reports were discovered."

    failures: dict[str, list[tuple[str, str]]] = {}
    for path, payload in reports:
        result = lint_report(payload)
        blocking = [
            issue
            for issue in result.get("issues", [])
            if isinstance(issue, dict)
            and str(issue.get("severity") or "").upper() in {"ERROR", "WARNING"}
        ]
        if result["valid"] and not blocking:
            continue
        failures[_relative(path)] = [
            (str(issue.get("code") or "unknown"), str(issue.get("path") or "$"))
            for issue in blocking
        ]

    assert not failures, failures


def test_example_json_artifacts_do_not_persist_credentials() -> None:
    failures: dict[str, list[str]] = {}
    for path in _example_json_files():
        sensitive_paths = find_sensitive_data_paths(_load_json(path))
        if sensitive_paths:
            failures[_relative(path)] = sensitive_paths

    assert not failures, failures


def test_example_text_reports_do_not_persist_credentials() -> None:
    failures: dict[str, list[str]] = {}
    text_paths = sorted(
        path
        for suffix in ("*.md", "*.html")
        for path in EXAMPLE_REPORTS_ROOT.rglob(suffix)
    )
    assert text_paths, "No Markdown or HTML example reports were discovered."
    for path in text_paths:
        sensitive_paths = find_sensitive_data_paths(
            path.read_text(encoding="utf-8", errors="replace")
        )
        if sensitive_paths:
            failures[_relative(path)] = sensitive_paths

    assert not failures, failures


def test_all_example_artifacts_pass_independent_provider_secret_canaries() -> None:
    """Scan text, JSON, evidence, and decompressed PDF streams independently."""

    failures: dict[str, list[str]] = {}
    artifact_paths = sorted(path for path in EXAMPLE_REPORTS_ROOT.rglob("*") if path.is_file())
    assert artifact_paths, "No example report artifacts were discovered."
    for path in artifact_paths:
        raw = path.read_bytes()
        chunks = [raw]
        if path.suffix.lower() == ".pdf":
            for marker in re.finditer(rb"stream\r?\n", raw):
                end = raw.find(b"endstream", marker.end())
                if end < 0:
                    continue
                encoded = raw[marker.end() : end].rstrip(b"\r\n")
                try:
                    chunks.append(zlib.decompress(encoded))
                except zlib.error:
                    continue
        matched = [
            name
            for name, pattern in INDEPENDENT_SECRET_PATTERNS.items()
            if any(pattern.search(chunk) for chunk in chunks)
        ]
        if matched:
            failures[_relative(path)] = matched

    assert not failures, failures


def test_example_evidence_manifests_match_artifacts_and_reports() -> None:
    manifest_paths = sorted(EXAMPLE_REPORTS_ROOT.rglob("evidence/manifest.json"))
    assert manifest_paths, "No example evidence manifests were discovered."

    failures: list[str] = []
    for manifest_path in manifest_paths:
        manifest = _load_json(manifest_path)
        report_dir = manifest_path.parent.parent
        artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
        if not isinstance(artifacts, list):
            failures.append(f"{_relative(manifest_path)}: artifacts is not a list")
            continue
        if manifest.get("artifact_count") != len(artifacts):
            failures.append(f"{_relative(manifest_path)}: artifact_count mismatch")

        report_file = report_dir / str(manifest.get("report_file") or "")
        report = _load_json(report_file) if report_file.is_file() else {}
        evidence_pack = report.get("evidence_pack") if isinstance(report, dict) else None
        report_artifacts = evidence_pack.get("artifacts") if isinstance(evidence_pack, dict) else None
        report_hashes = {
            str(item.get("path") or ""): str(item.get("sha256") or "")
            for item in report_artifacts or []
            if isinstance(item, dict)
        }

        for item in artifacts:
            if not isinstance(item, dict):
                failures.append(f"{_relative(manifest_path)}: non-object artifact entry")
                continue
            relative_artifact = str(item.get("path") or "")
            artifact_path = report_dir / relative_artifact
            if not artifact_path.is_file():
                failures.append(f"{_relative(manifest_path)}: missing {relative_artifact}")
                continue
            content = artifact_path.read_bytes()
            actual_sha256 = hashlib.sha256(content).hexdigest()
            expected_sha256 = str(item.get("sha256") or "")
            if expected_sha256 != actual_sha256:
                failures.append(f"{_relative(manifest_path)}: hash mismatch for {relative_artifact}")
            if item.get("bytes") != len(content):
                failures.append(f"{_relative(manifest_path)}: byte count mismatch for {relative_artifact}")
            if report_hashes.get(relative_artifact) != actual_sha256:
                failures.append(f"{_relative(report_file)}: hash mismatch for {relative_artifact}")

    assert not failures, failures
