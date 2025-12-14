from __future__ import annotations

from typing import Any, Dict, List, Tuple


DEFAULT_TOOL_ORDER: Tuple[str, ...] = (
    # Recon first
    "nmap",
    "masscan",
    "rustscan",
    # Web tooling
    "whatweb",
    "nuclei",
    "gobuster",
    "nikto",
    # Conditional modules
    "dnsenum",
    "sslscan",
    "enum4linux-ng",
    # Optional / special
    "sqlmap",
    "supabase_rls",
    "trivy",
)


def _tool_order_index(tool: str) -> int:
    tool = str(tool or "").strip()
    if not tool:
        return 10_000
    normalized = tool.replace("_", "-")
    try:
        return DEFAULT_TOOL_ORDER.index(normalized)
    except ValueError:
        return 9_999


def stable_sort_results(results: List[Any]) -> List[Any]:
    """
    Returns a new list with results in a stable, predictable order.

    Intended for audits where parallel execution would otherwise cause
    non-deterministic ordering in JSON/Markdown reports.
    """
    items: List[Any] = list(results or [])

    def key(item: Any) -> Tuple[Any, ...]:
        if not isinstance(item, dict):
            return (10_000, str(type(item)), str(item))
        tool = item.get("tool")
        tool_str = "" if tool is None else str(tool)
        tool_norm = tool_str.replace("_", "-")

        data = item.get("data")
        command = ""
        if isinstance(data, dict):
            cmd = data.get("command")
            if isinstance(cmd, str):
                command = cmd

        # Keep 'skipped' entries after successful entries within the same tool.
        skipped_rank = 1 if item.get("skipped") else 0
        success_rank = 0 if item.get("success") else 1

        return (_tool_order_index(tool_norm), tool_norm, skipped_rank, success_rank, command)

    return sorted(items, key=key)

