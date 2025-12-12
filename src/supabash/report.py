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

    # Summary
    summary = report.get("summary")
    if summary:
        if isinstance(summary, dict):
            lines.append("\n## Summary")
            lines.append(summary.get("summary", ""))
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

    return "\n".join(lines)


def write_markdown(report: Dict[str, Any], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_markdown(report)
    path.write_text(content)
    return str(path)
