from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class SupabaseAuditScanner:
    """
    Supabase-specific security checks driven by web targets.
    - Detect exposed Supabase project URLs on websites
    - Detect leaked anon/service_role keys in web content
    - Probe unauthenticated REST/RPC endpoints for exposure
    """

    SUPABASE_URL_RE = re.compile(r"https?://[a-z0-9-]{6,}\.supabase\.(?:co|in)", re.IGNORECASE)
    JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{2,}")
    KEY_ASSIGN_RE = re.compile(
        r"(?i)(supabase|anon|service(?:_role|role)?)\w*key\s*[:=]\s*['\"]([^'\"]{20,})['\"]"
    )
    RPC_CALL_RE = re.compile(r"\brpc\s*\(\s*['\"]([a-zA-Z0-9_]+)['\"]", re.IGNORECASE)

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def scan(
        self,
        targets: Sequence[str],
        *,
        max_pages: int = 5,
        supabase_urls_override: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[int] = None,
        cancel_event=None,
    ) -> Dict[str, Any]:
        urls = [str(u).strip() for u in list(targets or []) if str(u).strip()]
        if not urls:
            return {"success": False, "error": "No targets provided", "command": "supabase_audit"}

        max_pages = max(1, int(max_pages))
        resolved_timeout = resolve_timeout_seconds(timeout_seconds, default=10)

        found_supabase_urls: List[str] = []
        exposed_urls: List[Dict[str, str]] = []
        keys: List[Dict[str, str]] = []
        rpc_candidates: List[str] = []
        page_hits: List[Dict[str, Any]] = []

        for target in urls:
            if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                return {"success": False, "canceled": True, "command": "supabase_audit"}
            if len(page_hits) >= max_pages:
                break
            direct_matches = list({u for u in self.SUPABASE_URL_RE.findall(target)})
            for u in direct_matches:
                normalized = self._normalize_supabase_url(u)
                if normalized not in found_supabase_urls:
                    found_supabase_urls.append(normalized)
                exposed_urls.append({"supabase_url": normalized, "source": target})
            try:
                resp = self.session.get(target, timeout=resolved_timeout)
            except Exception as e:
                logger.debug(f"Supabase audit fetch failed for {target}: {e}")
                continue
            if resp is None:
                continue
            text = resp.text or ""
            if not text.strip():
                continue
            page_hits.append({"url": target, "status": resp.status_code})

            urls_found = list({u for u in self.SUPABASE_URL_RE.findall(text)})
            if urls_found:
                for u in urls_found:
                    normalized = self._normalize_supabase_url(u)
                    if normalized not in found_supabase_urls:
                        found_supabase_urls.append(normalized)
                    exposed_urls.append({"supabase_url": normalized, "source": target})

            for key_type, key_value in self._extract_keys(text):
                keys.append(
                    {
                        "type": key_type,
                        "value": self._mask_secret(key_value),
                        "source": target,
                    }
                )

            for rpc in self._extract_rpc_candidates(text):
                if rpc not in rpc_candidates:
                    rpc_candidates.append(rpc)

        if supabase_urls_override:
            for u in supabase_urls_override:
                normalized = self._normalize_supabase_url(u)
                if not normalized:
                    continue
                if normalized not in found_supabase_urls:
                    found_supabase_urls.append(normalized)
                exposed_urls.append({"supabase_url": normalized, "source": "override"})

        exposures = self._probe_supabase_endpoints(
            found_supabase_urls,
            rpc_candidates,
            timeout=resolved_timeout,
            cancel_event=cancel_event,
        )

        return {
            "success": True,
            "scanned": [p.get("url") for p in page_hits],
            "page_hits": page_hits,
            "supabase_urls": found_supabase_urls,
            "exposed_urls": exposed_urls,
            "keys": keys,
            "rpc_candidates": rpc_candidates,
            "exposures": exposures,
            "command": "supabase_audit",
        }

    def _normalize_supabase_url(self, url: str) -> str:
        return str(url or "").strip().rstrip("/")

    def _extract_rpc_candidates(self, text: str) -> List[str]:
        return [m.group(1) for m in self.RPC_CALL_RE.finditer(text or "") if m.group(1)]

    def _extract_keys(self, text: str) -> List[Tuple[str, str]]:
        found: List[Tuple[str, str]] = []
        for match in self.KEY_ASSIGN_RE.finditer(text or ""):
            raw_value = match.group(2)
            if raw_value:
                found.append((self._classify_key(raw_value, match.group(0)), raw_value))
        for token in self.JWT_RE.findall(text or ""):
            if not token:
                continue
            key_type = self._classify_key(token, text)
            found.append((key_type, token))
        return self._dedupe_keys(found)

    def _classify_key(self, value: str, context: str) -> str:
        payload = self._decode_jwt_payload(value)
        if isinstance(payload, dict):
            role = str(payload.get("role") or "").lower()
            if role == "service_role":
                return "service_role"
            if role == "anon":
                return "anon"
        ctx = (context or "").lower()
        if "service_role" in ctx or "service role" in ctx:
            return "service_role"
        if "anon" in ctx:
            return "anon"
        return "unknown"

    def _decode_jwt_payload(self, token: str) -> Optional[Dict[str, Any]]:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        try:
            data = base64.urlsafe_b64decode(padded.encode("utf-8"))
            payload = json.loads(data.decode("utf-8"))
            if isinstance(payload, dict):
                return payload
        except Exception:
            return None
        return None

    def _mask_secret(self, value: str) -> str:
        if not value:
            return ""
        trimmed = value.strip()
        if len(trimmed) <= 12:
            return trimmed
        return f"{trimmed[:6]}…{trimmed[-4:]}"

    def _dedupe_keys(self, keys: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        seen = set()
        out: List[Tuple[str, str]] = []
        for key_type, value in keys:
            if value in seen:
                continue
            seen.add(value)
            out.append((key_type, value))
        return out

    def _probe_supabase_endpoints(
        self,
        supabase_urls: List[str],
        rpc_candidates: List[str],
        *,
        timeout: int,
        cancel_event=None,
    ) -> List[Dict[str, Any]]:
        exposures: List[Dict[str, Any]] = []
        for base in supabase_urls:
            if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                return exposures
            rest_url = f"{base}/rest/v1/"
            rpc_root = f"{base}/rest/v1/rpc/"
            rls_url = f"{base}/rest/v1/"
            exposures.extend(self._probe_public_endpoint(rest_url, "rest_api_public", timeout))
            exposures.extend(self._probe_public_endpoint(rpc_root, "rpc_root_public", timeout))
            exposures.extend(self._probe_rls(rls_url, timeout))
            for rpc in rpc_candidates[:12]:
                rpc_url = f"{base}/rest/v1/rpc/{rpc}"
                exposures.extend(self._probe_rpc(rpc_url, rpc, timeout))
        return exposures

    def _probe_rls(self, url: str, timeout: int) -> List[Dict[str, Any]]:
        try:
            resp = self.session.get(url, timeout=timeout)
        except Exception as e:
            logger.debug(f"Supabase audit RLS probe failed for {url}: {e}")
            return []
        if resp is None:
            return []
        if resp.status_code in (200, 201, 204):
            return [
                {
                    "type": "rls_misconfig",
                    "url": url,
                    "status": resp.status_code,
                }
            ]
        return []

    def _probe_public_endpoint(self, url: str, kind: str, timeout: int) -> List[Dict[str, Any]]:
        try:
            resp = self.session.get(url, timeout=timeout)
        except Exception as e:
            logger.debug(f"Supabase audit probe failed for {url}: {e}")
            return []
        if resp is None:
            return []
        if resp.status_code in (200, 201, 204):
            return [
                {
                    "type": kind,
                    "url": url,
                    "status": resp.status_code,
                }
            ]
        return []

    def _probe_rpc(self, url: str, rpc_name: str, timeout: int) -> List[Dict[str, Any]]:
        try:
            resp = self.session.post(url, json={}, timeout=timeout)
        except Exception as e:
            logger.debug(f"Supabase audit RPC probe failed for {url}: {e}")
            return []
        if resp is None:
            return []
        if resp.status_code in (200, 201, 204):
            return [
                {
                    "type": "rpc_public",
                    "url": url,
                    "rpc": rpc_name,
                    "status": resp.status_code,
                }
            ]
        return []
