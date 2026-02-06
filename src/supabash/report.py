from pathlib import Path
from typing import Any, Dict, List, Tuple
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

COMPLIANCE_COVERAGE_ROWS: Dict[str, List[Dict[str, Any]]] = {
    "compliance_pci": [
        {"area": "CDE Asset & Service Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability Discovery & Exposure Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Transport Security Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Control Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_soc2": [
        {"area": "Security Surface Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability & Misconfiguration Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Encryption/Transport Control Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Control Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_iso": [
        {"area": "Asset Discovery & Service Mapping", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Technical Vulnerability Management", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Cryptographic Safeguard Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Management Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_dora": [
        {"area": "ICT Exposure Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability Handling Evidence", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Secure Communications Review", "tools": ["sslscan", "nmap"]},
        {"area": "Operational Access Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_nis2": [
        {"area": "Critical Service Exposure Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Vulnerability Detection Evidence", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Network Security & Encryption Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Control Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_gdpr": [
        {"area": "Personal Data Exposure Surface Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Security-of-Processing Technical Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Data-in-Transit Protection Review", "tools": ["sslscan", "nmap"]},
        {"area": "Access Restriction Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
    "compliance_bsi": [
        {"area": "Baseline Service Inventory", "tools": ["nmap", "httpx", "whatweb"]},
        {"area": "Technical Vulnerability Checks", "tools": ["nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]},
        {"area": "Transport Hardening Review", "tools": ["sslscan", "nmap"]},
        {"area": "Authentication & Access Exposure Review", "tools": ["hydra", "medusa", "crackmapexec", "supabase_audit"]},
    ],
}

def generate_markdown(report: Dict[str, Any]) -> str:
    lines = []
    target = report.get("target", "unknown")
    summary = report.get("summary")
    raw_findings = report.get("findings", [])
    has_summary = bool(summary)
    has_findings = isinstance(raw_findings, list) and len(raw_findings) > 0
    lines.append(f"# Supabash Audit (Readiness) Report\n")
    # Add markdown hard line breaks for header metadata so HTML/PDF render each item on its own line.
    lines.append(f"**Target:** {target}  ")
    lines.append("**Assessment Type:** Supabash Audit (Readiness)  ")
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

    # TOC (anchors match GitHub-style headings)
    lines.append("\n## Table of Contents")
    toc = [
        ("Summary", "#summary") if has_summary else None,
        ("Methodology", "#methodology"),
        ("Scope & Assumptions", "#scope--assumptions") if isinstance(compliance_profile, str) and compliance_profile.strip() else None,
        ("Compliance Coverage Matrix", "#compliance-coverage-matrix") if isinstance(compliance_profile, str) and compliance_profile.strip() else None,
        ("Agentic Expansion", "#agentic-expansion") if isinstance(report.get("ai_audit"), dict) else None,
        ("Findings Overview", "#findings-overview"),
        ("Findings (Detailed)", "#findings-detailed") if has_findings else None,
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
            findings = summary.get("findings", [])
            if findings:
                lines.append("\n### Findings")
                for f in findings:
                    sev = f.get("severity", "INFO").upper()
                    title = f.get("title", "")
                    evidence = f.get("evidence", "")
                    rec = f.get("recommendation", "")
                    lines.append(f"- **{sev}** {title}")
                    if evidence:
                        lines.append(f"  - Evidence: {evidence}")
                    if rec:
                        lines.append(f"  - Recommendation: {rec}")
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

    # Compliance coverage matrix (readiness boundaries and evidence sources)
    def _tool_status_index(results: Any) -> Dict[str, Dict[str, int]]:
        index: Dict[str, Dict[str, int]] = {}
        if not isinstance(results, list):
            return index
        for entry in results:
            if not isinstance(entry, dict):
                continue
            tool = str(entry.get("tool") or "").strip().lower()
            if not tool:
                continue
            slot = index.setdefault(tool, {"success": 0, "failed": 0, "skipped": 0})
            if bool(entry.get("skipped")):
                slot["skipped"] += 1
            elif bool(entry.get("success")):
                slot["success"] += 1
            else:
                slot["failed"] += 1
        return index

    def _coverage_status(tools: List[str], idx: Dict[str, Dict[str, int]]) -> Tuple[str, str, str]:
        normalized_tools = [str(t).strip().lower() for t in tools if str(t).strip()]
        if not normalized_tools:
            return ("Not Assessed", "none", "No automated checks mapped")
        successful = [t for t in normalized_tools if idx.get(t, {}).get("success", 0) > 0]
        failed_only = [t for t in normalized_tools if idx.get(t, {}).get("failed", 0) > 0 and idx.get(t, {}).get("success", 0) == 0]
        skipped_only = [t for t in normalized_tools if idx.get(t, {}).get("skipped", 0) > 0 and idx.get(t, {}).get("success", 0) == 0]
        if not successful:
            status = "Not Assessed"
        elif len(successful) == len(normalized_tools):
            status = "Covered"
        else:
            status = "Partial"

        evidence = ", ".join(successful[:4]) if successful else "none"
        if len(successful) > 4:
            evidence = f"{evidence}, ..."

        notes_parts: List[str] = []
        if failed_only:
            notes_parts.append(f"failed: {', '.join(failed_only[:3])}")
        if skipped_only:
            notes_parts.append(f"skipped: {', '.join(skipped_only[:3])}")
        if not notes_parts and successful:
            notes_parts.append("based on successful tool runs")
        notes = "; ".join(notes_parts) if notes_parts else "no supporting runs"
        return (status, evidence, notes)

    if isinstance(compliance_profile, str) and compliance_profile.strip():
        rows = COMPLIANCE_COVERAGE_ROWS.get(compliance_profile.strip(), [])
        status_index = _tool_status_index(report.get("results", []))
        lines.append("\n## Compliance Coverage Matrix")
        lines.append("| Control Area | Status | Evidence Source | Notes |")
        lines.append("|---|---|---|---|")
        for row in rows:
            if not isinstance(row, dict):
                continue
            area = str(row.get("area") or "").strip()
            tools = row.get("tools")
            tools_list = tools if isinstance(tools, list) else []
            if not area:
                continue
            status, evidence, notes = _coverage_status(tools_list, status_index)
            lines.append(f"| {area} | {status} | {evidence} | {notes} |")
        lines.append("\n- Status legend: `Covered` = all mapped checks succeeded, `Partial` = some succeeded, `Not Assessed` = no successful mapped checks.")

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

    summary_findings = []
    if isinstance(summary, dict):
        sf = summary.get("findings", [])
        if isinstance(sf, list):
            summary_findings = sf

    llm_counts = sev_counts(summary_findings) if summary_findings else None
    tool_counts = sev_counts(agg_findings)

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
        else:
            lines.append("- No severity normalization differences between summary and tool-level findings.")

    # Detailed Findings (aggregated)
    if isinstance(agg_findings, list) and agg_findings:
        lines.append("\n## Findings (Detailed)")
        if info_deduped > 0:
            lines.append(f"_Note: {info_deduped} repeated INFO findings were deduplicated for readability._")
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
                tags = [str(t).strip() for t in compliance_tags if str(t).strip()]
                if tags:
                    lines.append(f"  - Compliance Mapping: {'; '.join(tags)}")

    # Tools run (table + short notes)
    results = report.get("results", []) or []
    lines.append("\n## Tools Run")
    lines.append("| Tool | Status | Command |")
    lines.append("|---|---|---|")
    tool_notes = []
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
            tool_notes.append(f"- **{tool}**: SKIPPED - {entry['reason']}")
        if not skipped and not entry.get("success") and entry.get("error"):
            tool_notes.append(f"- **{tool}**: FAILED - {entry['error']}")
    if tool_notes:
        lines.append("\n### Tool Notes")
        lines.extend(tool_notes)

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
