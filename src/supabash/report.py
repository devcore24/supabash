from pathlib import Path
from typing import Dict, Any
import json

def generate_markdown(report: Dict[str, Any]) -> str:
    lines = []
    target = report.get("target", "unknown")
    lines.append(f"# Supabash Audit Report\n")
    lines.append(f"**Target:** {target}")
    if report.get("container_image"):
        lines.append(f"**Container Image:** {report['container_image']}")

    # Errors (if any)
    errors = []
    err = report.get("error")
    if isinstance(err, str) and err.strip():
        errors.append(err.strip())
    react = report.get("react")
    if isinstance(react, dict):
        planner = react.get("planner")
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
                        lines.append(f"  - Fix: {rec}")
        else:
            lines.append("\n## Summary")
            lines.append(str(summary))

    # Detailed Findings (aggregated)
    agg_findings = report.get("findings", [])
    if isinstance(agg_findings, list) and agg_findings:
        lines.append("\n## Findings (Detailed)")
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
                lines.append(f"  - Fix: {rec.strip()}")
            remediation = f.get("remediation")
            if isinstance(remediation, dict):
                steps = remediation.get("steps")
                if isinstance(steps, list) and steps:
                    lines.append("  - Steps:")
                    for s in steps[:8]:
                        if isinstance(s, str) and s.strip():
                            lines.append(f"    - {s.strip()}")
                code_sample = f.get("code_sample") or remediation.get("code_sample")
                if isinstance(code_sample, str) and code_sample.strip():
                    lines.append("  - Code sample:")
                    lines.append("```")
                    lines.append(code_sample.strip())
                    lines.append("```")

    lines.append("\n## Tools Run")
    for entry in report.get("results", []):
        tool = entry.get("tool", "unknown")
        if entry.get("skipped"):
            status = "⏭️ skipped"
        else:
            success = entry.get("success")
            status = "✅ success" if success else "❌ failed"
        lines.append(f"- **{tool}**: {status}")
        if entry.get("skipped") and entry.get("reason"):
            lines.append(f"  - Reason: {entry['reason']}")
        if not entry.get("skipped") and not entry.get("success") and entry.get("error"):
            lines.append(f"  - Error: {entry['error']}")

    # Auditability: exact commands executed (when available)
    commands = []
    for entry in report.get("results", []) or []:
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
