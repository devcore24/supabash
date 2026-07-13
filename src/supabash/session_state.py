import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from supabash.llm_context import prepare_json_payload
from supabash.secure_io import atomic_write_text


@dataclass(frozen=True)
class SessionStatePaths:
    path: Path


def default_chat_state_path() -> Path:
    override = str(os.getenv("SUPABASH_STATE_DIR") or "").strip()
    state_dir = Path(override).expanduser() if override else Path.cwd() / ".supabash"
    return state_dir.resolve() / "chat_state.json"


def save_state(path: Path, state: Dict[str, Any], *, max_chars: int = 250_000) -> Tuple[bool, bool]:
    """
    Save chat state to disk.
    Returns (success, truncated).
    """
    try:
        payload, truncated = prepare_json_payload(state, max_chars=max_chars, max_depth=12)
        atomic_write_text(path, payload)
        return True, truncated
    except Exception:
        return False, False


def load_state(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def clear_state(path: Path) -> bool:
    try:
        path.unlink(missing_ok=True)
        return True
    except Exception:
        return False

