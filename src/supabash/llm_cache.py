import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class CacheSettings:
    enabled: bool
    dir: Path
    ttl_seconds: int
    max_entries: int


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def make_cache_key(payload: Dict[str, Any]) -> str:
    """
    Build a stable cache key for an LLM request.
    IMPORTANT: Do not include API keys or secrets in the payload.
    """
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return _sha256_hex(canonical)


class LLMCache:
    def __init__(self, settings: CacheSettings):
        self.settings = settings
        self.dir = settings.dir

    def _path_for_key(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def get(self, key: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        if not self.settings.enabled:
            return None
        path = self._path_for_key(key)
        try:
            if not path.exists():
                return None
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            created = float(data.get("created_at", 0))
            ttl = int(self.settings.ttl_seconds)
            if ttl > 0 and created > 0 and (time.time() - created) > ttl:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                return None
            content = data.get("content")
            meta = data.get("meta")
            if not isinstance(content, str) or not isinstance(meta, dict):
                return None
            meta = dict(meta)
            meta["cached"] = True
            meta["cache_key"] = key
            return content, meta
        except Exception:
            return None

    def set(self, key: str, content: str, meta: Dict[str, Any]) -> None:
        if not self.settings.enabled:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            return
        path = self._path_for_key(key)
        try:
            payload = {
                "created_at": time.time(),
                "content": content,
                "meta": meta,
            }
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except Exception:
            return
        self._enforce_max_entries()

    def _enforce_max_entries(self) -> None:
        limit = int(self.settings.max_entries)
        if limit <= 0:
            return
        try:
            files = sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        except Exception:
            return
        excess = len(files) - limit
        if excess <= 0:
            return
        for p in files[:excess]:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                continue

