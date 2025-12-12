import json
from typing import Any, Dict, List, Tuple


def _truncate_str(value: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(value) <= max_chars:
        return value
    suffix = "...(truncated)"
    keep = max(0, max_chars - len(suffix))
    return value[:keep] + suffix


def _shrink(value: Any, max_string: int, max_list: int, max_depth: int, depth: int = 0) -> Any:
    if depth >= max_depth:
        return "<max_depth_reached>"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return _truncate_str(value, max_string)

    if isinstance(value, (bytes, bytearray)):
        return _truncate_str(value.decode("utf-8", errors="replace"), max_string)

    if isinstance(value, list):
        out: List[Any] = []
        limit = max(0, max_list)
        for item in value[:limit]:
            out.append(_shrink(item, max_string=max_string, max_list=max_list, max_depth=max_depth, depth=depth + 1))
        remaining = len(value) - len(out)
        if remaining > 0:
            out.append(f"...(truncated {remaining} items)")
        return out

    if isinstance(value, tuple):
        return _shrink(list(value), max_string=max_string, max_list=max_list, max_depth=max_depth, depth=depth)

    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if key.lower() in {"stdout", "stderr", "output", "raw", "raw_output", "scan_xml"}:
                if isinstance(v, str):
                    out[key] = _truncate_str(v, max_string)
                else:
                    out[key] = _truncate_str(str(v), max_string)
                continue
            out[key] = _shrink(v, max_string=max_string, max_list=max_list, max_depth=max_depth, depth=depth + 1)
        return out

    return _truncate_str(str(value), max_string)


def prepare_json_payload(
    obj: Any,
    max_chars: int = 12000,
    *,
    max_depth: int = 8,
) -> Tuple[str, bool]:
    """
    Return (json_string, truncated) where json_string is best-effort <= max_chars.
    This is a safety valve to keep tool output from overflowing LLM context.
    """
    raw = json.dumps(obj, ensure_ascii=False)
    if len(raw) <= max_chars:
        return raw, False

    max_string = 4000
    max_list = 200
    while True:
        shrunk = _shrink(obj, max_string=max_string, max_list=max_list, max_depth=max_depth)
        s = json.dumps(shrunk, ensure_ascii=False)
        if len(s) <= max_chars:
            return s, True
        if max_string <= 256 and max_list <= 10:
            break
        max_string = max(256, max_string // 2)
        max_list = max(10, max_list // 2)

    minimal = {
        "note": "payload too large; truncated aggressively",
        "type": str(type(obj)),
    }
    return _truncate_str(json.dumps(minimal, ensure_ascii=False), max_chars), True

