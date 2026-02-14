from pathlib import Path
from typing import Any, Dict, List, Tuple, Set, Optional
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
import re

COMPLIANCE_COVERAGE_ROWS: Dict[str, List[Dict[str, Any]]] = {
    "compliance_pci": [
        {"area": "CDE Asset & Service Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability Discovery & Exposure Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Transport Security Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Control Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_soc2": [
        {"area": "Security Surface Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability & Misconfiguration Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Encryption/Transport Control Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Control Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_iso": [
        {"area": "Asset Discovery & Service Mapping", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Technical Vulnerability Management", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Cryptographic Safeguard Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Management Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_dora": [
        {"area": "ICT Exposure Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability Handling Evidence", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Secure Communications Review", "tools": ["sslscan", "nmap"]},
        {"area": "Operational Access Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_nis2": [
        {"area": "Critical Service Exposure Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability Detection Evidence", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Network Security & Encryption Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Control Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_gdpr": [
        {"area": "Personal Data Exposure Surface Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Security-of-Processing Technical Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Data-in-Transit Protection Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Restriction Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_bsi": [
        {"area": "Baseline Service Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Technical Vulnerability Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Transport Hardening Review", "tools": ["sslscan", "nmap"]},
        {"area": "Authentication & Access Exposure Review", "tools": ["readiness_probe", "nuclei", "hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
}

NOT_ASSESSABLE_AREAS: Dict[str, List[str]] = {
    "compliance_pci": [
        "CDE boundary validation and cardholder data flow confirmation (CHD/SAD handling).",
        "Formal access recertification evidence and separation-of-duties approvals.",
        "Key management procedures and cryptographic key lifecycle controls.",
        "Third-party attestation activities (ASV, QSA validation, ROC/SAQ conclusions).",
    ],
    "compliance_soc2": [
        "Policy design/effectiveness over the audit period (not point-in-time scan evidence).",
        "Access review governance (JML workflow approvals and periodic recertifications).",
        "Change management control operation evidence (tickets, approvals, segregation).",
        "Incident response process effectiveness and tabletop/drill execution records.",
    ],
    "compliance_iso": [
        "ISMS governance operation, management review, and internal audit evidence.",
        "Risk treatment plan execution and exception acceptance workflow validation.",
        "Supplier assurance process execution and contractual control monitoring.",
        "Control operation effectiveness across the certification audit period.",
    ],
    "compliance_dora": [
        "ICT risk governance decisions and board-level oversight evidence.",
        "Third-party ICT service provider contractual and oversight process effectiveness.",
        "Operational resilience testing program effectiveness beyond technical scan outputs.",
        "Regulatory reporting process effectiveness and incident governance records.",
    ],
    "compliance_nis2": [
        "Organizational governance and management accountability evidence.",
        "Business continuity and crisis-management process effectiveness over time.",
        "Supply-chain security governance execution and contractual assurance evidence.",
        "Regulatory notification workflow effectiveness and audit trail completeness.",
    ],
    "compliance_gdpr": [
        "Data inventory and lawful basis validation for processing activities.",
        "Data subject rights workflow effectiveness and request handling governance.",
        "Processor/third-party contract assurance and transfer mechanism governance.",
        "DPIA process quality and privacy governance operation over time.",
    ],
    "compliance_bsi": [
        "ISMS governance and documented process operation evidence.",
        "Organizational role/accountability controls beyond technical exposure checks.",
        "Supplier and external interface governance effectiveness.",
        "Longitudinal control performance evidence required for formal assessments.",
    ],
}


def _has_payload(data: Any) -> bool:
    if data is None:
        return False
    if isinstance(data, str):
        return bool(data.strip())
    if isinstance(data, (list, dict, tuple, set)):
        return len(data) > 0
    return True


def _entry_has_effective_signal(tool: str, data: Any) -> bool:
    t = str(tool or "").strip().lower()
    if t == "supabase_audit" and isinstance(data, dict):
        # Avoid overstating access-control coverage when supabase_audit ran
        # successfully but found no meaningful exposure signal.
        for key in ("exposures", "keys", "exposed_urls", "rpc_candidates", "supabase_urls"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return True
            if isinstance(value, (list, dict, tuple, set)) and len(value) > 0:
                return True
        return False
    if t == "readiness_probe" and isinstance(data, dict):
        findings = data.get("findings")
        if isinstance(findings, list) and findings:
            return True
        checks = data.get("checks")
        if isinstance(checks, list) and checks:
            return True
        return False
    return _has_payload(data)


def _build_tool_status_index(results: Any) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    if not isinstance(results, list):
        return index
    for entry in results:
        if not isinstance(entry, dict):
            continue
        tool = str(entry.get("tool") or "").strip().lower()
        if not tool:
            continue
        slot = index.setdefault(
            tool,
            {
                "success": 0,
                "failed": 0,
                "skipped": 0,
                "failed_reasons": [],
                "skipped_reasons": [],
            },
        )
        if bool(entry.get("skipped")):
            slot["skipped"] += 1
            reason = str(entry.get("reason") or "").strip()
            if reason:
                reasons = slot.get("skipped_reasons")
                if isinstance(reasons, list) and reason not in reasons:
                    reasons.append(reason)
        elif bool(entry.get("success")):
            slot["success"] += 1
        else:
            slot["failed"] += 1
            reason = str(entry.get("error") or entry.get("reason") or "").strip()
            if reason:
                reasons = slot.get("failed_reasons")
                if isinstance(reasons, list) and reason not in reasons:
                    reasons.append(reason)
    return index


def _build_tool_signal_index(results: Any, findings: Any) -> Dict[str, Dict[str, Any]]:
    signal: Dict[str, Dict[str, Any]] = {}
    if isinstance(results, list):
        for entry in results:
            if not isinstance(entry, dict):
                continue
            tool = str(entry.get("tool") or "").strip().lower()
            if not tool:
                continue
            slot = signal.setdefault(tool, {"has_payload": False, "finding_count": 0})
            if bool(entry.get("success")) and not bool(entry.get("skipped")):
                data = entry.get("data")
                if _entry_has_effective_signal(tool, data):
                    slot["has_payload"] = True
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            tool = str(finding.get("tool") or "").strip().lower()
            if not tool:
                continue
            slot = signal.setdefault(tool, {"has_payload": False, "finding_count": 0})
            slot["finding_count"] = int(slot.get("finding_count", 0)) + 1
    return signal


def _sanitize_note_text(value: Any, max_len: int = 72) -> str:
    text = str(value or "").strip().replace("\n", " ").replace("\r", " ").replace("|", "/")
    text = re.sub(r"\s+", " ", text)
    if len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text


def _format_tool_reasons(
    tools: List[str],
    idx: Dict[str, Dict[str, Any]],
    key: str,
    label: str,
    max_tools: int = 3,
) -> Optional[str]:
    if not tools:
        return None
    rendered: List[str] = []
    for tool in tools[:max_tools]:
        reasons = idx.get(tool, {}).get(key, [])
        reason_text = ""
        if isinstance(reasons, list) and reasons:
            reason_text = _sanitize_note_text(reasons[0])
        if reason_text:
            rendered.append(f"{tool} ({reason_text})")
        else:
            rendered.append(tool)
    if len(tools) > max_tools:
        rendered.append("...")
    if not rendered:
        return None
    return f"{label}: {', '.join(rendered)}"


def _coverage_status_details(
    tools: List[str],
    idx: Dict[str, Dict[str, Any]],
    signal_idx: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    normalized_tools = [str(t).strip().lower() for t in tools if str(t).strip()]
    if not normalized_tools:
        return {
            "status": "Not Assessed",
            "evidence_source": "none",
            "notes": "No automated checks mapped",
            "coverage_basis": "no_mapped_checks",
        }

    successful = [t for t in normalized_tools if idx.get(t, {}).get("success", 0) > 0]
    evidence_tools = [
        t
        for t in successful
        if int(signal_idx.get(t, {}).get("finding_count", 0)) > 0
        or bool(signal_idx.get(t, {}).get("has_payload"))
    ]
    failed_only = [t for t in normalized_tools if idx.get(t, {}).get("failed", 0) > 0 and idx.get(t, {}).get("success", 0) == 0]
    skipped_only = [t for t in normalized_tools if idx.get(t, {}).get("skipped", 0) > 0 and idx.get(t, {}).get("success", 0) == 0]

    coverage_basis = "corroborated_findings"
    if not successful:
        status = "Not Assessed"
        if failed_only:
            coverage_basis = "execution_error"
        elif skipped_only:
            coverage_basis = "scope_or_config_gated"
        else:
            coverage_basis = "no_successful_runs"
    elif not evidence_tools:
        # Successful mapped checks but no meaningful signal/finding payload.
        # Treat as inconclusive rather than covered/partial.
        status = "Not Assessed"
        coverage_basis = "inconclusive_signal"
    elif len(successful) == len(normalized_tools) and len(evidence_tools) == len(successful):
        status = "Covered"
    else:
        status = "Partial"

    evidence = ", ".join(evidence_tools[:4]) if evidence_tools else "none"
    if len(evidence_tools) > 4:
        evidence = f"{evidence}, ..."

    notes_parts: List[str] = []
    failed_with_reason = _format_tool_reasons(failed_only, idx, "failed_reasons", "failed")
    if failed_with_reason:
        notes_parts.append(failed_with_reason)
    skipped_with_reason = _format_tool_reasons(skipped_only, idx, "skipped_reasons", "skipped")
    if skipped_with_reason:
        notes_parts.append(skipped_with_reason)
    if not successful and failed_only:
        notes_parts.append("coverage blocked by execution errors")
    if not successful and skipped_only and not failed_only:
        notes_parts.append("coverage gated by scope/config")
    if successful and not evidence_tools:
        notes_parts.append("successful runs produced no evidence payload/findings")
    if not notes_parts and evidence_tools:
        notes_parts.append("based on successful tool runs")
    notes = "; ".join(notes_parts) if notes_parts else "no supporting runs"
    return {
        "status": status,
        "evidence_source": evidence,
        "notes": notes,
        "coverage_basis": coverage_basis,
    }


def build_compliance_coverage_matrix(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    profile = str(report.get("compliance_profile") or "").strip()
    if not profile:
        return []
    rows = COMPLIANCE_COVERAGE_ROWS.get(profile, [])
    status_index = _build_tool_status_index(report.get("results", []))
    signal_index = _build_tool_signal_index(report.get("results", []), report.get("findings", []))
    matrix: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        area = str(row.get("area") or "").strip()
        tools = row.get("tools")
        tools_list = tools if isinstance(tools, list) else []
        if not area:
            continue
        details = _coverage_status_details(tools_list, status_index, signal_index)
        matrix.append(
            {
                "area": area,
                "status": details["status"],
                "evidence_source": details["evidence_source"],
                "notes": details["notes"],
                "coverage_basis": details["coverage_basis"],
                "mapped_tools": [str(t).strip().lower() for t in tools_list if str(t).strip()],
            }
        )
    return matrix

def build_recommended_next_actions(
    summary_items: List[Dict[str, Any]],
    tool_items: List[Dict[str, Any]],
    profile: Any,
) -> List[str]:
    source = summary_items if summary_items else tool_items
    signals: Set[str] = set()
    for item in source:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip().lower()
        evidence = str(item.get("evidence") or "").strip().lower()
        text = f"{title} {evidence}"
        if text:
            signals.add(text)

    def has_signal(*phrases: str) -> bool:
        for s in signals:
            for p in phrases:
                if p in s:
                    return True
        return False

    profile_key = str(profile or "").strip().lower()
    action_text = {
        "monitoring_debug": (
            "Restrict monitoring/debug endpoints to trusted admin or monitoring networks only; add authentication/authorization controls where supported."
        ),
        "redis_exposure": (
            "Harden Redis: require authentication/ACLs, bind to localhost or private interfaces, and block untrusted network access at the firewall."
        ),
        "postgres_exposure": (
            "Limit PostgreSQL exposure to required application hosts and enforce strong auth/TLS policies for database connectivity."
        ),
        "attack_surface": (
            "Reduce attack surface by closing unused listeners and rebinding critical services from wildcard interfaces to least-privilege network zones."
        ),
        "web_hardening": (
            "Apply baseline web hardening: security headers, method restrictions, and removal of unnecessary default/admin endpoints."
        ),
        "tls_hardening": (
            "Enforce transport security on externally reachable services and validate TLS configuration strength on non-standard service ports."
        ),
    }
    triggered: Set[str] = set()
    if has_signal("prometheus", "/metrics", "metrics endpoint", "status/config", "pprof", "debug endpoint"):
        triggered.add("monitoring_debug")
    if has_signal("redis", "6379", "without authentication", "no auth"):
        triggered.add("redis_exposure")
    if has_signal("postgres", "5432"):
        triggered.add("postgres_exposure")
    if has_signal("wildcard", "0.0.0.0", "open port", "service exposed", "non-standard http ports"):
        triggered.add("attack_surface")
    if has_signal("missing security headers", "allowed options method", "default page"):
        triggered.add("web_hardening")
    if has_signal("no tls", "cleartext", "tls", "ssl"):
        triggered.add("tls_hardening")

    ordered_keys_by_profile: Dict[str, List[str]] = {
        "compliance_pci": [
            "tls_hardening",
            "postgres_exposure",
            "redis_exposure",
            "monitoring_debug",
            "web_hardening",
            "attack_surface",
        ],
        "compliance_soc2": [
            "monitoring_debug",
            "attack_surface",
            "web_hardening",
            "tls_hardening",
            "postgres_exposure",
            "redis_exposure",
        ],
        "compliance_iso": [
            "attack_surface",
            "web_hardening",
            "tls_hardening",
            "monitoring_debug",
            "postgres_exposure",
            "redis_exposure",
        ],
        "compliance_dora": [
            "monitoring_debug",
            "attack_surface",
            "tls_hardening",
            "web_hardening",
            "postgres_exposure",
            "redis_exposure",
        ],
        "compliance_nis2": [
            "attack_surface",
            "monitoring_debug",
            "web_hardening",
            "tls_hardening",
            "postgres_exposure",
            "redis_exposure",
        ],
        "compliance_gdpr": [
            "tls_hardening",
            "monitoring_debug",
            "web_hardening",
            "attack_surface",
            "postgres_exposure",
            "redis_exposure",
        ],
        "compliance_bsi": [
            "attack_surface",
            "web_hardening",
            "monitoring_debug",
            "tls_hardening",
            "postgres_exposure",
            "redis_exposure",
        ],
    }
    default_order = [
        "monitoring_debug",
        "redis_exposure",
        "postgres_exposure",
        "attack_surface",
        "web_hardening",
        "tls_hardening",
    ]
    ordered_keys = ordered_keys_by_profile.get(profile_key, default_order)

    actions: List[str] = []
    for k in ordered_keys:
        if k in triggered:
            actions.append(action_text[k])

    if profile_key == "compliance_pci":
        actions.append(
            "Collect manual evidence for PCI readiness boundaries not automatable here (CDE scoping, CHD/SAD handling, key lifecycle, and formal control operation records)."
        )
    elif profile_key == "compliance_soc2":
        actions.append(
            "Collect SOC 2 control-operation evidence not assessable by scanning (JML/access reviews, change approvals, incident response drills, and policy governance records)."
        )
    elif profile_key:
        actions.append(
            "Collect manual control-operation evidence for governance/process controls not assessable by automated scanning (for readiness review)."
        )
    else:
        actions.append(
            "Collect manual operational evidence for controls not assessable by technical scanning (governance/process readiness)."
        )

    actions.append(
        "After remediation, rerun the readiness assessment and compare deltas in findings severity, exposed services, and evidence artifacts."
    )

    deduped: List[str] = []
    seen: Set[str] = set()
    for action in actions:
        text = str(action).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped[:8]

def generate_markdown(report: Dict[str, Any]) -> str:
    lines = []
    target = report.get("target", "unknown")
    summary = report.get("summary")
    raw_findings = report.get("findings", [])
    has_summary = bool(summary)
    has_findings = isinstance(raw_findings, list) and len(raw_findings) > 0
    lines.append(f"# Supabash Audit Report\n")
    # Add markdown hard line breaks for header metadata so HTML/PDF render each item on its own line.
    lines.append(f"**Target:** {target}  ")
    lines.append("**Assessment Type:** Supabash Audit  ")
    report_kind = report.get("report_kind")
    if isinstance(report_kind, str) and report_kind.strip():
        lines.append(f"**Run Type:** {report_kind.strip().replace('_', '-')}  ")
    if report.get("container_image"):
        lines.append(f"**Container Image:** {report['container_image']}  ")
    compliance_profile = report.get("compliance_profile")
    if isinstance(compliance_profile, str) and compliance_profile.strip():
        framework = report.get("compliance_framework")
        label = framework if isinstance(framework, str) and framework.strip() else compliance_profile
        lines.append(f"**Compliance Profile:** {label}  ")
    compliance_focus = report.get("compliance_focus")
    if isinstance(compliance_focus, str) and compliance_focus.strip():
        lines.append(f"**Compliance Focus:** {compliance_focus.strip()}  ")

    llm_meta = report.get("llm")
    if isinstance(llm_meta, dict) and llm_meta.get("enabled") is False:
        reason = llm_meta.get("reason") or "disabled"
        lines.append("\n## LLM")
        lines.append(f"- status: disabled ({reason})")

    # Timestamps (best-effort)
    def fmt_ts(ts: Any) -> str:
        try:
            if ts is None:
                return ""
            if isinstance(ts, bool):
                return ""
            val = float(ts)
            return datetime.fromtimestamp(val, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return ""

    started = fmt_ts(report.get("started_at"))
    finished = fmt_ts(report.get("finished_at"))
    if started or finished:
        lines.append("\n## Run Info")
        if started:
            lines.append(f"- started_at: {started}")
        if finished:
            lines.append(f"- finished_at: {finished}")

    def _normalize_mapping_text(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = re.sub(r"^\s*Potential\s+Gap:\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    # TOC (anchors match GitHub-style headings)
    lines.append("\n## Table of Contents")
    toc = [
        ("Summary", "#summary") if has_summary else None,
        ("Methodology", "#methodology"),
        ("Scope & Assumptions", "#scope--assumptions") if isinstance(compliance_profile, str) and compliance_profile.strip() else None,
        ("Compliance Coverage Matrix", "#compliance-coverage-matrix") if isinstance(compliance_profile, str) and compliance_profile.strip() else None,
        ("Not Assessable Automatically", "#not-assessable-automatically") if isinstance(compliance_profile, str) and compliance_profile.strip() else None,
        ("Evidence Pack", "#evidence-pack") if isinstance(report.get("evidence_pack"), dict) else None,
        ("Reproducibility Trace", "#reproducibility-trace") if isinstance(report.get("replay_trace"), dict) else None,
        ("LLM Reasoning Trace", "#llm-reasoning-trace") if isinstance(report.get("llm_reasoning_trace"), dict) else None,
        ("Agentic Expansion", "#agentic-expansion") if isinstance(report.get("ai_audit"), dict) else None,
        ("Findings Overview", "#findings-overview"),
        ("Findings (Detailed)", "#findings-detailed") if has_findings else None,
        ("Recommended Next Actions", "#recommended-next-actions") if has_findings else None,
        ("Tools Run", "#tools-run"),
        ("Commands Executed", "#commands-executed"),
    ]
    for item in toc:
        if not item:
            continue
        title, anchor = item
        lines.append(f"- [{title}]({anchor})")

    # Errors (if any)
    errors = []
    err = report.get("error")
    if isinstance(err, str) and err.strip():
        errors.append(err.strip())
    ai = report.get("ai_audit")
    if isinstance(ai, dict):
        planner = ai.get("planner")
        if isinstance(planner, dict):
            perr = planner.get("error")
            if isinstance(perr, str) and perr.strip() and perr.strip() not in errors:
                errors.append(perr.strip())
    if errors:
        lines.append("\n## Error")
        for e in errors[:3]:
            lines.append(f"- {e}")

    def _norm_key(value: Any) -> str:
        text = str(value or "").strip().lower()
        text = re.sub(r"[^a-z0-9]+", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    def _merge_summary_findings(
        summary_items: List[Dict[str, Any]],
        tool_items: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        order: List[Tuple[str, str]] = []

        for item in summary_items:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "INFO").upper()
            title = str(item.get("title") or "").strip()
            if not title:
                continue
            key = (sev, _norm_key(title))
            if key not in grouped:
                grouped[key] = {
                    "severity": sev,
                    "title": title,
                    "evidence_items": [],
                    "recommendation_items": [],
                    "corroborating_tools": [],
                    "compliance_mapping_items": [],
                    "mapping_sources": [],
                }
                order.append(key)
            evidence = str(item.get("evidence") or "").strip()
            if evidence and evidence not in grouped[key]["evidence_items"]:
                grouped[key]["evidence_items"].append(evidence)
            rec = str(item.get("recommendation") or "").strip()
            if rec and rec not in grouped[key]["recommendation_items"]:
                grouped[key]["recommendation_items"].append(rec)

        # Enrich summary items with corroborating evidence from tool findings.
        for item in tool_items:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "INFO").upper()
            title = str(item.get("title") or "").strip()
            if not title:
                continue
            key = (sev, _norm_key(title))
            if key not in grouped:
                continue
            evidence = str(item.get("evidence") or "").strip()
            tool = str(item.get("tool") or "").strip()
            if not evidence:
                continue
            support = f"{tool}: {evidence}" if tool else evidence
            if support not in grouped[key]["evidence_items"]:
                grouped[key]["evidence_items"].append(support)
            if tool and tool not in grouped[key]["corroborating_tools"]:
                grouped[key]["corroborating_tools"].append(tool)
            if tool and tool not in grouped[key]["mapping_sources"]:
                grouped[key]["mapping_sources"].append(tool)
            compliance_mappings = item.get("compliance_mappings")
            if isinstance(compliance_mappings, list):
                for mapping in compliance_mappings:
                    if not isinstance(mapping, dict):
                        continue
                    reference = str(mapping.get("reference") or "").strip()
                    confidence = str(mapping.get("confidence") or "").strip().lower()
                    if not reference:
                        continue
                    if confidence in ("low", "medium", "high"):
                        text = _normalize_mapping_text(f"{reference} (mapping confidence: {confidence})")
                    else:
                        text = _normalize_mapping_text(reference)
                    if text not in grouped[key]["compliance_mapping_items"]:
                        grouped[key]["compliance_mapping_items"].append(text)
            compliance_tags = item.get("compliance_tags")
            if isinstance(compliance_tags, list):
                for tag in compliance_tags:
                    text = _normalize_mapping_text(tag)
                    if text and text not in grouped[key]["compliance_mapping_items"]:
                        grouped[key]["compliance_mapping_items"].append(text)

        merged: List[Dict[str, Any]] = []
        for key in order:
            item = grouped[key]
            evidence_items = item.get("evidence_items") or []
            rec_items = item.get("recommendation_items") or []
            merged.append(
                {
                    "severity": item.get("severity", "INFO"),
                    "title": item.get("title", ""),
                    "evidence": evidence_items[0] if evidence_items else "",
                    "evidence_items": evidence_items,
                    "recommendation": rec_items[0] if rec_items else "",
                    "recommendation_items": rec_items,
                    "corroborating_tools": item.get("corroborating_tools", []),
                    "compliance_mapping_items": item.get("compliance_mapping_items", []),
                    "mapping_sources": item.get("mapping_sources", []),
                }
            )
        return merged

    summary_findings: List[Dict[str, Any]] = []
    if isinstance(summary, dict):
        sf = summary.get("findings", [])
        if isinstance(sf, list):
            summary_findings = _merge_summary_findings(
                [x for x in sf if isinstance(x, dict)],
                [x for x in raw_findings if isinstance(x, dict)],
            )
    if summary_findings and isinstance(raw_findings, list):
        sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        inv_rank = {v: k for k, v in sev_rank.items()}

        def _norm_sev(value: Any) -> str:
            s = str(value or "INFO").strip().upper()
            return s if s in sev_rank else "INFO"

        def _title_norm(value: Any) -> str:
            text = str(value or "").strip().lower()
            # Strip trailing tool marker, e.g. "(nuclei)".
            text = re.sub(r"\s+\([^()]+\)\s*$", "", text)
            text = re.sub(r"[^a-z0-9]+", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            return text

        raw_max_by_title: Dict[str, int] = {}
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            title_key = _title_norm(f.get("title"))
            if not title_key:
                continue
            rank = sev_rank[_norm_sev(f.get("severity"))]
            raw_max_by_title[title_key] = max(raw_max_by_title.get(title_key, 0), rank)

        summary_keys: Set[str] = set()
        for sf_item in summary_findings:
            if not isinstance(sf_item, dict):
                continue
            title_key = _title_norm(sf_item.get("title"))
            if title_key:
                summary_keys.add(title_key)
            current_rank = sev_rank[_norm_sev(sf_item.get("severity"))]
            best_rank = raw_max_by_title.get(title_key, current_rank)
            if best_rank <= current_rank and title_key:
                for raw_key, raw_rank in raw_max_by_title.items():
                    if not raw_key:
                        continue
                    if title_key in raw_key or raw_key in title_key:
                        if raw_rank > best_rank:
                            best_rank = raw_rank
            if best_rank > current_rank:
                sf_item["severity"] = inv_rank.get(best_rank, "INFO")

        # Ensure any CRITICAL tool findings are reflected in summary findings.
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            if _norm_sev(f.get("severity")) != "CRITICAL":
                continue
            title = str(f.get("title") or "").strip()
            title_key = _title_norm(title)
            if not title_key or title_key in summary_keys:
                continue
            summary_findings.append(
                {
                    "severity": "CRITICAL",
                    "title": re.sub(r"\s+\([^()]+\)\s*$", "", title).strip() or title,
                    "evidence": str(f.get("evidence") or "").strip(),
                    "evidence_items": [str(f.get("evidence") or "").strip()] if str(f.get("evidence") or "").strip() else [],
                    "recommendation": str(f.get("recommendation") or "").strip(),
                    "recommendation_items": [str(f.get("recommendation") or "").strip()]
                    if str(f.get("recommendation") or "").strip()
                    else [],
                    "corroborating_tools": [str(f.get("tool") or "").strip()] if str(f.get("tool") or "").strip() else [],
                    "compliance_mapping_items": [],
                    "mapping_sources": [],
                }
            )
            summary_keys.add(title_key)
    evidence_artifact_index: Dict[str, List[str]] = {}
    evidence_manifest_path = ""
    evidence_pack_for_summary = report.get("evidence_pack")
    if isinstance(evidence_pack_for_summary, dict):
        manifest = evidence_pack_for_summary.get("manifest")
        if isinstance(manifest, str) and manifest.strip():
            evidence_manifest_path = manifest.strip()
        artifacts = evidence_pack_for_summary.get("artifacts")
        if isinstance(artifacts, list):
            for artifact in artifacts:
                if not isinstance(artifact, dict):
                    continue
                tool = str(artifact.get("tool") or "").strip().lower()
                path = str(artifact.get("path") or "").strip()
                status = str(artifact.get("status") or "").strip().lower()
                if not tool or not path or status == "skipped":
                    continue
                slot = evidence_artifact_index.setdefault(tool, [])
                if path not in slot:
                    slot.append(path)

    # Summary
    if summary:
        if isinstance(summary, dict):
            lines.append("\n## Summary")
            lines.append(summary.get("summary", ""))
            summary_notes = report.get("summary_notes")
            if isinstance(summary_notes, list) and summary_notes:
                lines.append("\n### Notes")
                for note in summary_notes:
                    if isinstance(note, str) and note.strip():
                        lines.append(f"- {note.strip()}")
            llm_meta = report.get("llm")
            if isinstance(llm_meta, dict):
                calls = llm_meta.get("calls")
                if isinstance(calls, list) and calls:
                    lines.append("\n### LLM Usage")
                    total_tokens = 0
                    total_cost = 0.0
                    have_cost = False
                    providers = set()
                    models = set()
                    for c in calls:
                        if not isinstance(c, dict):
                            continue
                        provider = c.get("provider")
                        if isinstance(provider, str) and provider.strip():
                            providers.add(provider.strip())
                        model = c.get("model")
                        if isinstance(model, str) and model.strip():
                            models.add(model.strip())
                        usage = c.get("usage")
                        if isinstance(usage, dict):
                            tt = usage.get("total_tokens")
                            if isinstance(tt, int):
                                total_tokens += tt
                        cost = c.get("cost_usd")
                        if isinstance(cost, (int, float)):
                            total_cost += float(cost)
                            have_cost = True
                    if total_tokens:
                        lines.append(f"- total_tokens={total_tokens}")
                    if have_cost:
                        lines.append(f"- cost_usd={total_cost:.6f}")
                    if providers:
                        lines.append(f"- provider={', '.join(sorted(providers))}")
                    if models:
                        lines.append(f"- model={', '.join(sorted(models))}")
                else:
                    usage = llm_meta.get("usage")
                    cost = llm_meta.get("cost_usd")
                    if isinstance(usage, dict) or cost is not None:
                        lines.append("\n### LLM Usage")
                        if isinstance(usage, dict):
                            pt = usage.get("prompt_tokens")
                            ct = usage.get("completion_tokens")
                            tt = usage.get("total_tokens")
                            parts = []
                            if tt is not None:
                                parts.append(f"total_tokens={tt}")
                            if pt is not None:
                                parts.append(f"prompt_tokens={pt}")
                            if ct is not None:
                                parts.append(f"completion_tokens={ct}")
                            if parts:
                                lines.append(f"- {' | '.join(parts)}")
                        if cost is not None:
                            try:
                                lines.append(f"- cost_usd={float(cost):.6f}")
                            except Exception:
                                lines.append(f"- cost_usd={cost}")
                        provider = llm_meta.get("provider")
                        if isinstance(provider, str) and provider.strip():
                            lines.append(f"- provider={provider.strip()}")
                        model = llm_meta.get("model")
                        if isinstance(model, str) and model.strip():
                            lines.append(f"- model={model.strip()}")
            if summary_findings:
                lines.append("\n### Findings")
                for f in summary_findings:
                    sev = f.get("severity", "INFO").upper()
                    title = f.get("title", "")
                    evidence_items = [str(x).strip() for x in (f.get("evidence_items") or []) if str(x).strip()]
                    rec_items = [str(x).strip() for x in (f.get("recommendation_items") or []) if str(x).strip()]
                    lines.append(f"- **{sev}** {title}")
                    if evidence_items:
                        if len(evidence_items) == 1:
                            lines.append(f"  - Evidence: {evidence_items[0]}")
                        else:
                            lines.append("  - Evidence:")
                            for ev in evidence_items[:5]:
                                lines.append(f"    - {ev}")
                    if rec_items:
                        if len(rec_items) == 1:
                            lines.append(f"  - Recommendation: {rec_items[0]}")
                        else:
                            lines.append("  - Recommendations:")
                            for rec in rec_items[:3]:
                                lines.append(f"    - {rec}")
                    compliance_mapping_items = [
                        str(x).strip()
                        for x in (f.get("compliance_mapping_items") or [])
                        if str(x).strip()
                    ]
                    if compliance_mapping_items:
                        lines.append("  - Compliance Mapping:")
                        for mapping in compliance_mapping_items[:3]:
                            lines.append(f"    - Potential Gap: {_normalize_mapping_text(mapping)}")
                        mapping_sources = [
                            str(x).strip().lower()
                            for x in (f.get("mapping_sources") or [])
                            if str(x).strip()
                        ]
                        if mapping_sources:
                            lines.append(f"  - Mapping Basis: corroborated by {', '.join(sorted(set(mapping_sources)))} findings")
                    corroborating_tools = [
                        str(t).strip().lower()
                        for t in (f.get("corroborating_tools") or [])
                        if str(t).strip()
                    ]
                    artifact_refs: List[str] = []
                    for tool in corroborating_tools:
                        for path in evidence_artifact_index.get(tool, [])[:2]:
                            if path not in artifact_refs:
                                artifact_refs.append(path)
                    if artifact_refs:
                        refs = ", ".join(f"`{p}`" for p in artifact_refs[:4])
                        lines.append(f"  - Evidence Artifacts: {refs}")
                        if evidence_manifest_path:
                            lines.append(f"  - Manifest Reference: `{evidence_manifest_path}`")
        else:
            lines.append("\n## Summary")
            lines.append(str(summary))
            summary_notes = report.get("summary_notes")
            if isinstance(summary_notes, list) and summary_notes:
                lines.append("\n### Notes")
                for note in summary_notes:
                    if isinstance(note, str) and note.strip():
                        lines.append(f"- {note.strip()}")

    # Methodology
    lines.append("\n## Methodology")
    lines.append("- Baseline: deterministic evidence collection with scope controls and safe defaults.")
    if isinstance(report.get("ai_audit"), dict):
        lines.append("- Agentic expansion: tool-calling planner proposes additional evidence collection within allowed scope.")
    else:
        lines.append("- Agentic expansion: not enabled for this run.")
    if isinstance(compliance_profile, str) and compliance_profile.strip():
        framework = report.get("compliance_framework")
        label = framework.strip() if isinstance(framework, str) and framework.strip() else compliance_profile.strip()
        lines.append(f"- Compliance profile: {label}")
    if isinstance(compliance_focus, str) and compliance_focus.strip():
        lines.append(f"- Compliance focus: {compliance_focus.strip()}")

    # Scope & assumptions for compliance readiness runs
    def _target_host(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            if "://" in raw:
                return (urlparse(raw).hostname or "").strip().lower()
            return raw.split("/")[0].split(":")[0].strip().lower()
        except Exception:
            return raw.lower()

    if isinstance(compliance_profile, str) and compliance_profile.strip():
        lines.append("\n## Scope & Assumptions")
        web_targets = report.get("web_targets")
        in_scope = []
        if isinstance(target, str) and target.strip():
            in_scope.append(target.strip())
        if isinstance(web_targets, list):
            for w in web_targets:
                ws = str(w).strip()
                if ws and ws not in in_scope:
                    in_scope.append(ws)
        image = report.get("container_image")
        if isinstance(image, str) and image.strip():
            in_scope.append(f"container-image:{image.strip()}")
        if in_scope:
            lines.append(f"- In scope: {', '.join(in_scope[:8])}{' ...' if len(in_scope) > 8 else ''}")
        lines.append("- Authentication context: unauthenticated network/web checks unless explicitly configured otherwise.")
        lines.append("- Control mapping note: mapped controls indicate potential relevance and require manual validation.")

        host = _target_host(target)
        if host in ("localhost", "127.0.0.1", "::1"):
            lines.append("- Localhost limitation: this run cannot validate external exposure paths or network segmentation boundaries.")

        if compliance_profile.strip() == "compliance_pci":
            lines.append("- PCI scope caveat: this run does not confirm whether services store/process/transmit CHD or SAD.")

        lines.append("- Out of scope: independent attestation/certification decisions and control operation effectiveness testing.")

    if isinstance(compliance_profile, str) and compliance_profile.strip():
        matrix_rows = report.get("compliance_coverage_matrix")
        if not isinstance(matrix_rows, list):
            matrix_rows = build_compliance_coverage_matrix(report)
            report["compliance_coverage_matrix"] = matrix_rows
        lines.append("\n## Compliance Coverage Matrix")
        lines.append("| Control Area | Status | Evidence Source | Notes |")
        lines.append("|---|---|---|---|")
        for row in matrix_rows:
            if not isinstance(row, dict):
                continue
            area = str(row.get("area") or "").strip()
            if not area:
                continue
            status = str(row.get("status") or "Not Assessed").strip()
            evidence = str(row.get("evidence_source") or "none").strip() or "none"
            notes = str(row.get("notes") or "").strip()
            basis = str(row.get("coverage_basis") or "").strip()
            if basis:
                notes = f"basis={basis}; {notes}" if notes else f"basis={basis}"
            lines.append(f"| {area} | {status} | {evidence} | {notes} |")
        lines.append(
            "\n- Status legend: `Covered` = mapped checks succeeded with corroborating evidence, "
            "`Partial` = some mapped checks/evidence present, `Not Assessed` = no successful mapped checks "
            "or signal was inconclusive."
        )

        not_assessable = NOT_ASSESSABLE_AREAS.get(compliance_profile.strip(), [])
        if not_assessable:
            lines.append("\n## Not Assessable Automatically")
            lines.append("- The following areas require manual validation, process evidence, or third-party assessment:")
            for item in not_assessable:
                lines.append(f"- {item}")

    evidence_pack = report.get("evidence_pack")
    if isinstance(evidence_pack, dict):
        lines.append("\n## Evidence Pack")
        ep_dir = evidence_pack.get("dir")
        ep_manifest = evidence_pack.get("manifest")
        ep_count = evidence_pack.get("artifact_count")
        if isinstance(ep_dir, str) and ep_dir.strip():
            lines.append(f"- directory: `{ep_dir.strip()}`")
        if isinstance(ep_manifest, str) and ep_manifest.strip():
            lines.append(f"- manifest: `{ep_manifest.strip()}`")
        if isinstance(ep_count, int):
            lines.append(f"- artifact_count: {ep_count}")

        runtime = evidence_pack.get("runtime")
        if isinstance(runtime, dict) and runtime:
            lines.append("\n### Runtime Metadata")
            pyv = runtime.get("python_version")
            if isinstance(pyv, str) and pyv.strip():
                lines.append(f"- python_version: {pyv.strip()}")
            plat = runtime.get("platform")
            if isinstance(plat, str) and plat.strip():
                lines.append(f"- platform: {plat.strip()}")
            providers = runtime.get("llm_providers")
            if isinstance(providers, list) and providers:
                vals = [str(v).strip() for v in providers if str(v).strip()]
                if vals:
                    lines.append(f"- llm_providers: {', '.join(vals)}")
            models = runtime.get("llm_models")
            if isinstance(models, list) and models:
                vals = [str(v).strip() for v in models if str(v).strip()]
                if vals:
                    lines.append(f"- llm_models: {', '.join(vals)}")
            tool_versions = runtime.get("tool_versions")
            if isinstance(tool_versions, dict) and tool_versions:
                lines.append("\n### Tool Versions")
                for tool_name in sorted(tool_versions.keys()):
                    version = str(tool_versions.get(tool_name) or "").strip()
                    if version:
                        lines.append(f"- `{tool_name}`: {version}")

    replay_trace = report.get("replay_trace")
    if isinstance(replay_trace, dict):
        lines.append("\n## Reproducibility Trace")
        replay_file = replay_trace.get("file")
        replay_md_file = replay_trace.get("markdown_file")
        replay_steps = replay_trace.get("step_count")
        replay_ver = replay_trace.get("version")
        if isinstance(replay_file, str) and replay_file.strip():
            lines.append(f"- file: `{replay_file.strip()}`")
        if isinstance(replay_md_file, str) and replay_md_file.strip():
            lines.append(f"- markdown_file: `{replay_md_file.strip()}`")
        if isinstance(replay_steps, int):
            lines.append(f"- step_count: {replay_steps}")
        if isinstance(replay_ver, int):
            lines.append(f"- version: {replay_ver}")

    llm_reasoning_trace = report.get("llm_reasoning_trace")
    if isinstance(llm_reasoning_trace, dict):
        lines.append("\n## LLM Reasoning Trace")
        trace_json = llm_reasoning_trace.get("json_file")
        trace_md = llm_reasoning_trace.get("markdown_file")
        trace_events = llm_reasoning_trace.get("event_count")
        trace_steps = llm_reasoning_trace.get("decision_steps")
        trace_calls = llm_reasoning_trace.get("llm_calls")
        trace_ver = llm_reasoning_trace.get("version")
        if isinstance(trace_json, str) and trace_json.strip():
            lines.append(f"- json_file: `{trace_json.strip()}`")
        if isinstance(trace_md, str) and trace_md.strip():
            lines.append(f"- markdown_file: `{trace_md.strip()}`")
        if isinstance(trace_events, int):
            lines.append(f"- llm_event_count: {trace_events}")
        if isinstance(trace_steps, int):
            lines.append(f"- decision_steps: {trace_steps}")
        if isinstance(trace_calls, int):
            lines.append(f"- llm_calls: {trace_calls}")
        if isinstance(trace_ver, int):
            lines.append(f"- version: {trace_ver}")
        lines.append(
            "- note: captures explicit planner rationale/messages and decisions; hidden model internals are not included."
        )

    # Agentic expansion details (if present)
    ai = report.get("ai_audit")
    if isinstance(ai, dict):
        lines.append("\n## Agentic Expansion")
        phase = ai.get("phase")
        if isinstance(phase, str) and phase.strip():
            lines.append(f"- phase: {phase.strip()}")
        baseline_finished = fmt_ts(ai.get("baseline_finished_at"))
        if baseline_finished:
            lines.append(f"- baseline_finished_at: {baseline_finished}")
        max_actions = ai.get("max_actions")
        if isinstance(max_actions, int):
            lines.append(f"- max_actions: {max_actions}")
        notes = ai.get("notes")
        if isinstance(notes, str) and notes.strip():
            lines.append(f"- notes: {notes.strip()}")
        decision_trace = ai.get("decision_trace")
        if isinstance(decision_trace, list):
            lines.append(f"- decision_steps: {len(decision_trace)}")
        planner = ai.get("planner")
        if isinstance(planner, dict):
            ptype = planner.get("type")
            if isinstance(ptype, str) and ptype.strip():
                lines.append(f"- planner: {ptype.strip()}")
            warn = planner.get("warning")
            if isinstance(warn, str) and warn.strip():
                lines.append(f"- planner_warning: {warn.strip()}")
            perr = planner.get("error")
            if isinstance(perr, str) and perr.strip():
                lines.append(f"- planner_error: {perr.strip()}")
        if isinstance(decision_trace, list) and decision_trace:
            lines.append("\n### Decision Trace Highlights")
            for step in decision_trace[:20]:
                if not isinstance(step, dict):
                    continue
                step_no = step.get("iteration")
                decision = step.get("decision") if isinstance(step.get("decision"), dict) else {}
                decision_result = str(decision.get("result") or "unknown").strip() or "unknown"
                decision_reason = str(decision.get("reason") or "").strip()
                line = f"- step {step_no}: {decision_result}"
                if decision_reason:
                    line = f"{line} ({decision_reason})"
                lines.append(line)
                planner_view = step.get("planner") if isinstance(step.get("planner"), dict) else {}
                if planner_view:
                    candidates = planner_view.get("candidates")
                    if isinstance(candidates, list) and candidates:
                        top = candidates[0] if isinstance(candidates[0], dict) else {}
                        if isinstance(top, dict):
                            tool = str(top.get("tool") or "").strip()
                            target = str(top.get("target") or "").strip()
                            priority = top.get("priority")
                            top_line = f"tool={tool or '-'}"
                            if target:
                                top_line = f"{top_line} target={target}"
                            if priority is not None:
                                top_line = f"{top_line} priority={priority}"
                            lines.append(f"  - initial_candidate: {top_line}")
                replan = step.get("replan") if isinstance(step.get("replan"), dict) else {}
                if replan:
                    attempted = bool(replan.get("attempted"))
                    reason = str(replan.get("reason") or "").strip()
                    excluded_count = replan.get("excluded_count")
                    lines.append(
                        f"  - replan: attempted={str(attempted).lower()} reason={reason or '-'} excluded={excluded_count}"
                    )
                replans = step.get("planner_replans")
                if isinstance(replans, list) and replans:
                    first_replan = replans[0] if isinstance(replans[0], dict) else {}
                    if isinstance(first_replan, dict):
                        candidates = first_replan.get("candidates")
                        if isinstance(candidates, list) and candidates:
                            top = candidates[0] if isinstance(candidates[0], dict) else {}
                            if isinstance(top, dict):
                                tool = str(top.get("tool") or "").strip()
                                target = str(top.get("target") or "").strip()
                                priority = top.get("priority")
                                replan_line = f"tool={tool or '-'}"
                                if target:
                                    replan_line = f"{replan_line} target={target}"
                                if priority is not None:
                                    replan_line = f"{replan_line} priority={priority}"
                                lines.append(f"  - replan_candidate: {replan_line}")
                selected = step.get("selected_action") if isinstance(step.get("selected_action"), dict) else {}
                if selected:
                    tool = str(selected.get("tool") or "").strip()
                    target = str(selected.get("target") or "").strip()
                    lines.append(f"  - selected_action: {tool or '-'}{f' target={target}' if target else ''}")
        actions = ai.get("actions")
        if isinstance(actions, list) and actions:
            lines.append("\n### Actions")
            for a in actions[:50]:
                if not isinstance(a, dict):
                    continue
                status = "skipped" if a.get("skipped") else ("success" if a.get("success") else "failed")
                tool = str(a.get("tool") or "").strip()
                target = str(a.get("target") or "").strip()
                profile = str(a.get("profile") or "").strip()
                err = a.get("error")
                reason = a.get("reason")
                reasoning = a.get("reasoning")
                parts = []
                if tool:
                    parts.append(f"{tool}")
                if target:
                    parts.append(f"target={target}")
                if profile:
                    parts.append(f"profile={profile}")
                action_line = " ".join(parts).strip()
                if action_line:
                    line = f"- {action_line}: {status}"
                    lines.append(line)
                    if isinstance(reasoning, str) and reasoning.strip():
                        lines.append(f"  - Rationale: {reasoning.strip()}")
                    if status == "skipped":
                        if isinstance(reason, str) and reason.strip():
                            lines.append(f"  - Reason: {reason.strip()}")
                        elif isinstance(err, str) and err.strip():
                            lines.append(f"  - Reason: {err.strip()}")
                    elif isinstance(err, str) and err.strip():
                        lines.append(f"  - Error: {err.strip()}")

    # Findings overview table
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    def sev_counts(findings: Any) -> Dict[str, int]:
        counts = {k: 0 for k in sev_order}
        if not isinstance(findings, list):
            return counts
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", "INFO")).upper()
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1
        return counts

    agg_findings = raw_findings if isinstance(raw_findings, list) else []

    def dedupe_info_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        if not findings:
            return findings, 0
        seen = set()
        deduped: List[Dict[str, Any]] = []
        removed = 0
        for f in findings:
            if not isinstance(f, dict):
                deduped.append(f)
                continue
            sev = str(f.get("severity", "")).upper()
            if sev != "INFO":
                deduped.append(f)
                continue
            title = str(f.get("title", "")).strip().lower()
            evidence = str(f.get("evidence", "")).strip().lower()
            tool = str(f.get("tool", "")).strip().lower()
            key = (title, evidence, tool)
            if key in seen:
                removed += 1
                continue
            seen.add(key)
            deduped.append(f)
        return deduped, removed

    agg_findings, info_deduped = dedupe_info_findings(agg_findings)

    llm_counts = sev_counts(summary_findings) if summary_findings else None
    tool_counts = sev_counts(agg_findings)
    if llm_counts:
        llm_counts["CRITICAL"] = max(llm_counts.get("CRITICAL", 0), tool_counts.get("CRITICAL", 0))

    lines.append("\n## Findings Overview")
    if summary_findings:
        lines.append("\n### Summary (LLM)")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        for sev in sev_order:
            lines.append(f"| {sev} | {llm_counts[sev]} |")
        lines.append("\n### Detailed (Tools)")

    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in sev_order:
        lines.append(f"| {sev} | {tool_counts[sev]} |")

    if llm_counts:
        promotions = []
        reductions = []
        for sev in sev_order:
            delta = llm_counts.get(sev, 0) - tool_counts.get(sev, 0)
            if delta > 0:
                promotions.append(f"{sev}+{delta}")
            elif delta < 0:
                reductions.append(f"{sev}{delta}")
        lines.append("\n### Risk Normalization")
        if promotions or reductions:
            if promotions:
                lines.append(f"- Promoted in summary risk synthesis: {', '.join(promotions)}")
            if reductions:
                lines.append(f"- Reduced in summary risk synthesis: {', '.join(reductions)}")
            lines.append("- Basis: LLM summary may aggregate multiple low-signal findings into higher-level operational risk statements.")
            # Deterministic transparency layer for promoted summary findings.
            def _norm_text(value: Any) -> str:
                return str(value or "").strip().lower()

            def _norm_key(value: Any) -> str:
                s = _norm_text(value)
                s = re.sub(r"\s+", " ", s)
                return s

            def _parse_open_ports(findings: List[Dict[str, Any]]) -> List[int]:
                ports: Set[int] = set()
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    title = _norm_text(f.get("title"))
                    if not title.startswith("open port"):
                        continue
                    m = re.search(r"open port\s+(\d+)", title)
                    if not m:
                        continue
                    try:
                        ports.add(int(m.group(1)))
                    except Exception:
                        continue
                return sorted(ports)

            def _infer_rules(summary_item: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[str]:
                text = f"{_norm_text(summary_item.get('title'))} {_norm_text(summary_item.get('evidence'))}".strip()
                if not text:
                    return []

                ports = _parse_open_ports(findings)
                web_ports: List[int] = []
                unknown_ports: List[int] = []
                db_ports: Set[int] = set()
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    evidence = _norm_text(f.get("evidence"))
                    title = _norm_text(f.get("title"))
                    port_match = re.search(r"open port\s+(\d+)", title)
                    port = None
                    if port_match:
                        try:
                            port = int(port_match.group(1))
                        except Exception:
                            port = None
                    if any(token in evidence for token in ("http", "https", "express", "nginx", "apache", "golang net/http", "http-proxy")) and port is not None:
                        web_ports.append(port)
                    if "unknown" in evidence and port is not None:
                        unknown_ports.append(port)
                    if any(token in evidence for token in ("postgres", "postgresql", "redis")) or (port in (5432, 6379)):
                        if port is not None:
                            db_ports.add(port)

                rules: List[str] = []
                if any(k in text for k in ("database", "postgres", "redis", "cache")) and db_ports:
                    rules.append(f"rule:data_store_exposure_aggregation (ports: {', '.join(str(p) for p in sorted(db_ports))})")
                if any(k in text for k in ("http", "web", "application services", "surface")) and len(set(web_ports)) >= 2:
                    rules.append(f"rule:web_surface_aggregation (ports: {', '.join(str(p) for p in sorted(set(web_ports))[:8])})")
                if any(k in text for k in ("unknown", "unidentified", "non-standard", "legacy")) and (unknown_ports or ports):
                    details = ", ".join(str(p) for p in sorted(set(unknown_ports))[:8]) if unknown_ports else ", ".join(str(p) for p in ports[:8])
                    rules.append(f"rule:unclassified_service_aggregation (ports: {details})")
                if not rules and len(findings) >= 5:
                    rules.append(f"rule:llm_risk_synthesis (aggregated from {len(findings)} tool findings)")
                return rules

            tool_title_keys = {_norm_key(f.get("title")) for f in agg_findings if isinstance(f, dict)}
            promoted_detail_lines: List[str] = []
            for sf in summary_findings:
                if not isinstance(sf, dict):
                    continue
                sev = str(sf.get("severity", "INFO")).upper()
                if sev == "INFO":
                    continue
                title_key = _norm_key(sf.get("title"))
                title_text = str(sf.get("title") or "").strip()
                # Show details only for likely promoted/aggregated summary-level statements.
                if title_key and title_key in tool_title_keys:
                    continue
                rules = _infer_rules(sf, agg_findings)
                if not rules:
                    continue
                promoted_detail_lines.append(f"- {sev} {title_text}")
                promoted_detail_lines.append(f"  - Derived via: {'; '.join(rules)}")

            if promoted_detail_lines:
                lines.append("\n#### Normalization Details")
                lines.extend(promoted_detail_lines)
        else:
            lines.append("- No severity normalization differences between summary and tool-level findings.")

    # Detailed Findings (aggregated)
    if isinstance(agg_findings, list) and agg_findings:
        lines.append("\n## Findings (Detailed)")
        if info_deduped > 0:
            lines.append(f"_Note: {info_deduped} repeated INFO findings were deduplicated for readability._")
        def _correlated_signal_hints(findings: List[Dict[str, Any]]) -> List[str]:
            grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                title = str(finding.get("title") or "").strip()
                if not title:
                    continue
                sev = str(finding.get("severity") or "INFO").upper()
                key = (sev, _norm_key(title))
                slot = grouped.setdefault(
                    key,
                    {
                        "severity": sev,
                        "title": title,
                        "count": 0,
                        "tools": set(),
                        "evidence": set(),
                    },
                )
                slot["count"] = int(slot.get("count", 0)) + 1
                tool = str(finding.get("tool") or "").strip().lower()
                if tool:
                    slot["tools"].add(tool)
                evidence = str(finding.get("evidence") or "").strip()
                if evidence:
                    slot["evidence"].add(evidence)

            def _sev_rank(sev: str) -> int:
                order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                return order.get(sev, 99)

            hints: List[str] = []
            ranked = sorted(
                grouped.values(),
                key=lambda g: (_sev_rank(str(g.get("severity") or "INFO")), str(g.get("title") or "").lower()),
            )
            for g in ranked:
                count = int(g.get("count", 0))
                evidence_count = len(g.get("evidence", set()))
                if count < 2 or evidence_count < 2:
                    continue
                sev = str(g.get("severity") or "INFO").upper()
                title = str(g.get("title") or "").strip()
                tools = sorted(str(t) for t in (g.get("tools") or set()) if str(t))
                tool_part = f"; tools={', '.join(tools)}" if tools else ""
                hints.append(
                    f"- **{sev}** {title}: {count} correlated observations across {evidence_count} distinct evidence entries{tool_part}."
                )
            return hints

        correlated_hints = _correlated_signal_hints(agg_findings)
        if correlated_hints:
            lines.append("\n### Correlated Signals")
            lines.extend(correlated_hints[:12])
        # Blank line before list to ensure markdown parsers render list items correctly in HTML/PDF.
        lines.append("")
        for f in agg_findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", "INFO")).upper()
            title = str(f.get("title", ""))
            tool = f.get("tool")
            suffix = f" ({tool})" if tool else ""
            lines.append(f"- **{sev}** {title}{suffix}")
            evidence = f.get("evidence")
            if isinstance(evidence, str) and evidence.strip():
                lines.append(f"  - Evidence: {evidence.strip()}")
            rec = f.get("recommendation")
            if isinstance(rec, str) and rec.strip():
                lines.append(f"  - Recommendation: {rec.strip()}")
            remediation = f.get("remediation")
            if isinstance(remediation, dict):
                steps = remediation.get("steps")
                if isinstance(steps, list) and steps:
                    lines.append("  - Remediation Steps:")
                    for s in steps[:8]:
                        if isinstance(s, str) and s.strip():
                            lines.append(f"    - {s.strip()}")
                code_sample = f.get("code_sample") or remediation.get("code_sample")
                if isinstance(code_sample, str) and code_sample.strip():
                    lines.append("  - Code sample:")
                    lines.append("```")
                    lines.append(code_sample.strip())
                    lines.append("```")
            compliance_mappings = f.get("compliance_mappings")
            if isinstance(compliance_mappings, list) and compliance_mappings:
                mapping_parts = []
                for m in compliance_mappings:
                    if not isinstance(m, dict):
                        continue
                    ref = str(m.get("reference") or "").strip()
                    confidence = str(m.get("confidence") or "").strip().lower()
                    if not ref:
                        continue
                    if confidence in ("low", "medium", "high"):
                        mapping_parts.append(f"Potential Gap: {ref} (mapping confidence: {confidence})")
                    else:
                        mapping_parts.append(f"Potential Gap: {ref}")
                if mapping_parts:
                    lines.append(f"  - Compliance Mapping: {'; '.join(mapping_parts)}")
            compliance_tags = f.get("compliance_tags")
            if isinstance(compliance_tags, list) and compliance_tags and not isinstance(compliance_mappings, list):
                tags = [_normalize_mapping_text(t) for t in compliance_tags if _normalize_mapping_text(t)]
                if tags:
                    mapped = [f"Potential Gap: {t}" for t in tags]
                    lines.append(f"  - Compliance Mapping: {'; '.join(mapped)}")

    recommended_actions = build_recommended_next_actions(summary_findings, agg_findings, compliance_profile)
    report["recommended_next_actions"] = recommended_actions
    if recommended_actions:
        lines.append("\n## Recommended Next Actions")
        for idx, action in enumerate(recommended_actions, start=1):
            lines.append(f"{idx}. {action}")

    # Tools run (table + short notes)
    results = report.get("results", []) or []
    lines.append("\n## Tools Run")
    lines.append("| Tool | Status | Command |")
    lines.append("|---|---|---|")
    tool_notes: List[str] = []
    tool_note_counts: Dict[str, int] = {}
    def _add_tool_note(note: str) -> None:
        text = str(note or "").strip()
        if not text:
            return
        if text not in tool_note_counts:
            tool_notes.append(text)
            tool_note_counts[text] = 0
        tool_note_counts[text] += 1
    for entry in results:
        if not isinstance(entry, dict):
            continue
        tool = entry.get("tool", "unknown")
        skipped = bool(entry.get("skipped"))
        if skipped:
            status = "skipped"
        else:
            success = entry.get("success")
            status = "success" if success else "failed"
        cmd = entry.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            data = entry.get("data")
            if isinstance(data, dict):
                cmd = data.get("command")
        cmd_cell = f"`{cmd.strip()}`" if isinstance(cmd, str) and cmd.strip() else ""
        lines.append(f"| {tool} | {status} | {cmd_cell} |")
        if skipped and entry.get("reason"):
            _add_tool_note(f"- **{tool}**: SKIPPED - {entry['reason']}")
        if not skipped and not entry.get("success") and entry.get("error"):
            _add_tool_note(f"- **{tool}**: FAILED - {entry['error']}")
    if tool_notes:
        lines.append("\n### Tool Notes")
        for note in tool_notes:
            count = int(tool_note_counts.get(note, 1))
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(f"{note}{suffix}")

    # Auditability: exact commands executed (when available)
    commands = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        tool = entry.get("tool", "unknown")
        cmd = entry.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            data = entry.get("data")
            if isinstance(data, dict):
                cmd = data.get("command")
        if isinstance(cmd, str) and cmd.strip():
            commands.append((str(tool), cmd.strip()))
    if commands:
        lines.append("\n## Commands Executed")
        for tool, cmd in commands:
            lines.append(f"- **{tool}**: `{cmd}`")

    return "\n".join(lines)


def write_markdown(report: Dict[str, Any], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_markdown(report)
    path.write_text(content)
    return str(path)
