from pathlib import Path
from typing import Dict, Any
import json
from datetime import datetime, timezone

def generate_markdown(report: Dict[str, Any]) -> str:
    lines = []
    target = report.get("target", "unknown")
    lines.append(f"# Supabash Audit Report\n")
    lines.append(f"**Target:** {target}")
    report_kind = report.get("report_kind")
    if isinstance(report_kind, str) and report_kind.strip():
        lines.append(f"**Run Type:** {report_kind.strip().replace('_', '-')}")
    if report.get("container_image"):
        lines.append(f"**Container Image:** {report['container_image']}")
    compliance_profile = report.get("compliance_profile")
    if isinstance(compliance_profile, str) and compliance_profile.strip():
        framework = report.get("compliance_framework")
        label = framework if isinstance(framework, str) and framework.strip() else compliance_profile
        lines.append(f"**Compliance Profile:** {label}")
    compliance_focus = report.get("compliance_focus")
    if isinstance(compliance_focus, str) and compliance_focus.strip():
        lines.append(f"**Compliance Focus:** {compliance_focus.strip()}")

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
        ("Summary", "#summary"),
        ("Methodology", "#methodology"),
        ("Agentic Expansion", "#agentic-expansion") if isinstance(report.get("ai_audit"), dict) else None,
        ("Findings Overview", "#findings-overview"),
        ("Findings (Detailed)", "#findings-detailed"),
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
    summary = report.get("summary")
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
                    for c in calls:
                        if not isinstance(c, dict):
                            continue
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
        lines.append(f"- Compliance profile: {compliance_profile.strip()}")
    if isinstance(compliance_focus, str) and compliance_focus.strip():
        lines.append(f"- Compliance focus: {compliance_focus.strip()}")

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

    agg_findings = report.get("findings", [])
    if not isinstance(agg_findings, list):
        agg_findings = []

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

    lines.append("\n## Findings Overview")
    if summary_findings:
        lines.append("\n### Summary (LLM)")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        counts = sev_counts(summary_findings)
        for sev in sev_order:
            lines.append(f"| {sev} | {counts[sev]} |")
        lines.append("\n### Detailed (Tools)")

    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    counts = sev_counts(agg_findings)
    for sev in sev_order:
        lines.append(f"| {sev} | {counts[sev]} |")

    # Detailed Findings (aggregated)
    if isinstance(agg_findings, list) and agg_findings:
        lines.append("\n## Findings (Detailed)")
        if info_deduped > 0:
            lines.append(f"_Note: {info_deduped} repeated INFO findings were deduplicated for readability._")
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
            compliance_tags = f.get("compliance_tags")
            if isinstance(compliance_tags, list) and compliance_tags:
                tags = [str(t).strip() for t in compliance_tags if str(t).strip()]
                if tags:
                    lines.append(f"  - Compliance Impact: {'; '.join(tags)}")

    # Tools run (table + short notes)
    results = report.get("results", []) or []
    lines.append("\n## Tools Run")
    lines.append("| Tool | Status | Command |")
    lines.append("|---|---|---|")
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
            lines.append(f"- **{tool}**: ⏭️ skipped — {entry['reason']}")
        if not skipped and not entry.get("success") and entry.get("error"):
            lines.append(f"- **{tool}**: ❌ failed — {entry['error']}")

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
