from __future__ import annotations

from typing import Any, Dict, List, Optional


def tool_key_variants(tool: str) -> List[str]:
    tool = str(tool or "").strip()
    if not tool:
        return []
    keys = [tool]
    if "-" in tool:
        keys.append(tool.replace("-", "_"))
    if "_" in tool:
        keys.append(tool.replace("_", "-"))
    out: List[str] = []
    for k in keys:
        if k not in out:
            out.append(k)
    return out


def get_tool_config(config: Any, tool: str) -> Dict[str, Any]:
    """
    Returns the dict for tools.<tool> from a config object, supporting '-'/'_' variants.
    """
    if not isinstance(config, dict):
        return {}
    tools_cfg = config.get("tools", {})
    if not isinstance(tools_cfg, dict):
        return {}
    for k in tool_key_variants(tool):
        v = tools_cfg.get(k)
        if isinstance(v, dict):
            return v
    return {}


def get_tool_timeout_seconds(config: Any, tool: str) -> Optional[int]:
    cfg = get_tool_config(config, tool)
    if not cfg:
        return None
    value = cfg.get("timeout_seconds", cfg.get("timeout"))
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def resolve_timeout_seconds(specified: Any, *, default: Optional[int]) -> Optional[int]:
    """
    Resolves a timeout value:
      - specified is None -> default
      - specified <= 0 -> None (no timeout)
      - otherwise -> int(specified)
    """
    if specified is None:
        return default
    try:
        value = int(specified)
    except Exception:
        return default
    if value <= 0:
        return None
    return value

