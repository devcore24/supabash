from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set


DEFAULT_BASELINE_PATH = "tests/fixtures/webgoat/webgoat-main-exploits.json"

# These are useful for learning, but not exploit-oriented coverage targets.
EXCLUDED_MODULES_FOR_EXPLOIT_COVERAGE = {
    "webgoatintroduction",
    "webwolfintroduction",
    "lessontemplate",
    "chromedevtools",
    "cia",
    "httpbasics",
    "httpproxies",
}

MODULE_KEYWORDS: Dict[str, List[str]] = {
    "authbypass": ["auth bypass", "authentication bypass", "2fa bypass"],
    "bypassrestrictions": ["bypass restriction", "front end restriction", "frontend validation"],
    "clientsidefiltering": ["client side filtering", "client-side filtering"],
    "csrf": ["csrf", "cross site request forgery", "cross-site request forgery"],
    "deserialization": ["deserialization", "insecure deserialization"],
    "hijacksession": ["session hijack", "hijack session", "session fixation"],
    "htmltampering": ["html tampering", "tamper html"],
    "idor": ["idor", "insecure direct object reference", "object level authorization"],
    "insecurelogin": ["insecure login", "weak login"],
    "jwt": ["jwt", "json web token", "alg none", "kid", "jku"],
    "logging": ["log spoof", "log injection", "sensitive logging", "log leakage"],
    "missingac": ["missing access control", "function level access control", "access control"],
    "openredirect": ["open redirect", "unvalidated redirect"],
    "passwordreset": ["password reset", "reset token", "security question"],
    "pathtraversal": ["path traversal", "directory traversal", "zip slip", "../", "..\\"],
    "securepasswords": ["password policy", "secure password"],
    "securitymisconfiguration": [
        "security misconfiguration",
        "misconfiguration",
        "default credential",
        "stack trace",
        "actuator",
    ],
    "spoofcookie": ["spoof cookie", "cookie tampering", "session cookie"],
    "sqlinjection": ["sql injection", "sqli", "union select", "boolean based blind"],
    "ssrf": ["ssrf", "server side request forgery", "server-side request forgery"],
    "vulnerablecomponents": ["vulnerable component", "outdated component", "known vulnerable"],
    "xss": [
        "cross site scripting",
        "cross-site scripting",
        "dom xss",
        "stored xss",
        "reflected xss",
        "script alert",
    ],
    "xxe": ["xxe", "xml external entity"],
}

_WORD_RE = re.compile(r"[^a-z0-9]+")


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    return _WORD_RE.sub(" ", text).strip()


def _unique_strings(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for v in values:
        n = _normalize_text(v)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out


def _module_keywords(module: str) -> List[str]:
    raw: List[str] = []
    raw.extend(MODULE_KEYWORDS.get(module, []))
    raw.append(module)
    raw.append(module.replace("_", " "))
    raw.append(module.replace("-", " "))
    return _unique_strings(raw)


def _finding_blob(finding: Dict[str, Any]) -> str:
    parts = [
        finding.get("title"),
        finding.get("evidence"),
        finding.get("recommendation"),
        finding.get("tool"),
        finding.get("risk_class"),
        finding.get("phase"),
    ]
    return _normalize_text(" ".join(str(p) for p in parts if p is not None))


def _dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = finding.get("dedup_key")
        if not isinstance(key, str) or not key.strip():
            key = "|".join(
                [
                    _normalize_text(finding.get("severity")),
                    _normalize_text(finding.get("title")),
                    _normalize_text(finding.get("evidence")),
                    _normalize_text(finding.get("tool")),
                ]
            )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _match_modules(
    findings: List[Dict[str, Any]],
    modules: List[str],
) -> Dict[str, List[int]]:
    matches: Dict[str, List[int]] = {}
    for module in modules:
        kws = _module_keywords(module)
        if not kws:
            continue
        for idx, finding in enumerate(findings):
            blob = _finding_blob(finding)
            if not blob:
                continue
            padded = f" {blob} "
            for kw in kws:
                if f" {kw} " in padded:
                    matches.setdefault(module, []).append(idx)
                    break
    return matches


def _infer_section_module(section: str, modules: List[str]) -> Optional[str]:
    normalized = _normalize_text(section)
    if not normalized:
        return None
    best_module: Optional[str] = None
    best_len = -1
    padded = f" {normalized} "
    for module in modules:
        for kw in _module_keywords(module):
            if f" {kw} " in padded and len(kw) > best_len:
                best_module = module
                best_len = len(kw)
    return best_module


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        sev = str(finding.get("severity") or "").strip().upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def compare_report_to_baseline(
    report: Dict[str, Any],
    baseline: Dict[str, Any],
    *,
    report_path: Optional[str] = None,
    baseline_path: Optional[str] = None,
) -> Dict[str, Any]:
    findings_raw = report.get("findings")
    findings = _dedup_findings(findings_raw if isinstance(findings_raw, list) else [])
    modules = [str(m).strip() for m in baseline.get("lesson_modules", []) if str(m).strip()]
    wiki_sections = [
        str(s).strip()
        for s in baseline.get("wiki_main_exploit_sections", [])
        if str(s).strip()
    ]

    module_matches = _match_modules(findings, modules)
    matched_modules = sorted(module_matches.keys())
    exploit_modules = sorted([m for m in modules if m not in EXCLUDED_MODULES_FOR_EXPLOIT_COVERAGE])
    matched_exploit_modules = sorted(
        [m for m in matched_modules if m in exploit_modules]
    )
    missing_exploit_modules = sorted(
        [m for m in exploit_modules if m not in matched_exploit_modules]
    )

    section_to_module: Dict[str, str] = {}
    for section in wiki_sections:
        module = _infer_section_module(section, modules)
        if module:
            section_to_module[section] = module
    covered_sections = sorted(
        [s for s, module in section_to_module.items() if module in matched_modules]
    )
    uncovered_sections = sorted(
        [s for s in wiki_sections if s not in covered_sections]
    )

    sev_counts = _severity_counts(findings)
    high_critical_indexes = [
        i
        for i, finding in enumerate(findings)
        if str(finding.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
    ]
    matched_high_critical_indexes = sorted(
        {
            idx
            for module, indexes in module_matches.items()
            if module in matched_modules
            for idx in indexes
            if idx in high_critical_indexes
        }
    )
    unmatched_high_critical_indexes = sorted(
        [idx for idx in high_critical_indexes if idx not in matched_high_critical_indexes]
    )

    total_findings = len(findings)
    non_info_count = total_findings - sev_counts.get("INFO", 0)
    non_info_ratio = (non_info_count / total_findings) if total_findings else 0.0

    exploit_coverage_pct = (
        (len(matched_exploit_modules) / len(exploit_modules)) * 100.0
        if exploit_modules
        else 0.0
    )
    high_critical_match_pct = (
        (len(matched_high_critical_indexes) / len(high_critical_indexes)) * 100.0
        if high_critical_indexes
        else 100.0
    )
    signal_quality_pct = non_info_ratio * 100.0
    overall_score = round(
        (exploit_coverage_pct * 0.50)
        + (high_critical_match_pct * 0.35)
        + (signal_quality_pct * 0.15),
        1,
    )

    matches_by_module: Dict[str, List[str]] = {}
    for module in matched_modules:
        titles = []
        seen: Set[str] = set()
        for idx in module_matches.get(module, []):
            title = str(findings[idx].get("title") or "").strip()
            if not title:
                continue
            if title in seen:
                continue
            seen.add(title)
            titles.append(title)
            if len(titles) >= 3:
                break
        matches_by_module[module] = titles

    unmatched_high_critical = []
    for idx in unmatched_high_critical_indexes:
        finding = findings[idx]
        unmatched_high_critical.append(
            {
                "severity": str(finding.get("severity") or ""),
                "title": str(finding.get("title") or ""),
                "tool": str(finding.get("tool") or ""),
            }
        )

    return {
        "dataset": "webgoat_scan_comparison",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_path": report_path,
        "baseline_path": baseline_path,
        "target": report.get("target"),
        "score": {
            "overall_0_100": overall_score,
            "exploit_coverage_pct": round(exploit_coverage_pct, 1),
            "high_critical_match_pct": round(high_critical_match_pct, 1),
            "signal_quality_pct": round(signal_quality_pct, 1),
        },
        "totals": {
            "findings_deduped": total_findings,
            "severity": sev_counts,
            "high_critical_total": len(high_critical_indexes),
            "high_critical_matched": len(matched_high_critical_indexes),
        },
        "coverage": {
            "exploit_modules_total": len(exploit_modules),
            "exploit_modules_matched": len(matched_exploit_modules),
            "exploit_modules_missing": len(missing_exploit_modules),
            "matched_exploit_modules": matched_exploit_modules,
            "missing_exploit_modules": missing_exploit_modules,
        },
        "wiki_section_coverage": {
            "sections_total": len(wiki_sections),
            "sections_mapped_to_modules": len(section_to_module),
            "sections_covered": len(covered_sections),
            "sections_uncovered": len(uncovered_sections),
            "covered_sections_sample": covered_sections[:12],
            "uncovered_sections_sample": uncovered_sections[:12],
        },
        "matches_by_module": matches_by_module,
        "unmatched_high_critical_findings": unmatched_high_critical,
        "notes": [
            "This comparison estimates topic-level coverage against WebGoat lessons and the Main-Exploits wiki.",
            "Many WebGoat lessons are interactive/authenticated; black-box scanners cannot fully solve all lesson flows.",
        ],
    }


def render_markdown(result: Dict[str, Any]) -> str:
    score = result.get("score", {})
    coverage = result.get("coverage", {})
    totals = result.get("totals", {})
    wiki_cov = result.get("wiki_section_coverage", {})
    matched_modules = coverage.get("matched_exploit_modules", [])
    missing_modules = coverage.get("missing_exploit_modules", [])
    unmatched_hc = result.get("unmatched_high_critical_findings", [])

    lines: List[str] = []
    lines.append("# WebGoat Comparator Report")
    lines.append("")
    lines.append(f"- Target: `{result.get('target')}`")
    lines.append(f"- Overall score: **{score.get('overall_0_100', 0)} / 100**")
    lines.append(f"- Generated at: `{result.get('generated_at', '')}`")
    lines.append("")
    lines.append("## Score Breakdown")
    lines.append("")
    lines.append(
        f"- Exploit coverage: **{score.get('exploit_coverage_pct', 0)}%** "
        f"({coverage.get('exploit_modules_matched', 0)}/{coverage.get('exploit_modules_total', 0)} modules)"
    )
    lines.append(
        f"- HIGH/CRITICAL match quality: **{score.get('high_critical_match_pct', 0)}%** "
        f"({totals.get('high_critical_matched', 0)}/{totals.get('high_critical_total', 0)})"
    )
    lines.append(f"- Signal quality (non-INFO): **{score.get('signal_quality_pct', 0)}%**")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(
        f"- Wiki sections covered: **{wiki_cov.get('sections_covered', 0)}/{wiki_cov.get('sections_total', 0)}** "
        f"(mapped: {wiki_cov.get('sections_mapped_to_modules', 0)})"
    )
    lines.append("- Matched exploit modules:")
    if matched_modules:
        for module in matched_modules:
            lines.append(f"  - `{module}`")
    else:
        lines.append("  - none")
    lines.append("- Missing exploit modules:")
    if missing_modules:
        for module in missing_modules[:20]:
            lines.append(f"  - `{module}`")
    else:
        lines.append("  - none")
    lines.append("")
    lines.append("## Unmatched HIGH/CRITICAL Findings")
    lines.append("")
    if unmatched_hc:
        for finding in unmatched_hc:
            lines.append(
                f"- **{finding.get('severity', '')}** {finding.get('title', '')} "
                f"(tool: `{finding.get('tool', '')}`)"
            )
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    for note in result.get("notes", []):
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return data


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _default_output_paths(report_path: Path) -> tuple[Path, Path]:
    stem = report_path.stem
    out_json = report_path.with_name(f"{stem}-webgoat-compare.json")
    out_md = report_path.with_name(f"{stem}-webgoat-compare.md")
    return out_json, out_md


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Compare a Supabash audit report JSON against WebGoat baseline coverage."
    )
    p.add_argument("--report", required=True, help="Path to Supabash report JSON")
    p.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE_PATH,
        help="Path to WebGoat baseline JSON",
    )
    p.add_argument("--out-json", default=None, help="Path to write comparator JSON")
    p.add_argument("--out-md", default=None, help="Path to write comparator markdown")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    report_path = Path(args.report).expanduser().resolve()
    baseline_path = Path(args.baseline).expanduser().resolve()
    report = _read_json(report_path)
    baseline = _read_json(baseline_path)

    result = compare_report_to_baseline(
        report,
        baseline,
        report_path=str(report_path),
        baseline_path=str(baseline_path),
    )
    md = render_markdown(result)

    default_json, default_md = _default_output_paths(report_path)
    out_json = Path(args.out_json).expanduser().resolve() if args.out_json else default_json
    out_md = Path(args.out_md).expanduser().resolve() if args.out_md else default_md

    _write_text(out_json, json.dumps(result, indent=2))
    _write_text(out_md, md)

    score = result.get("score", {})
    coverage = result.get("coverage", {})
    print(
        f"[webgoat-compare] score={score.get('overall_0_100', 0)} "
        f"coverage={coverage.get('exploit_modules_matched', 0)}/{coverage.get('exploit_modules_total', 0)} "
        f"high_crit_match={score.get('high_critical_match_pct', 0)}%"
    )
    print(f"[webgoat-compare] json={out_json}")
    print(f"[webgoat-compare] md={out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
