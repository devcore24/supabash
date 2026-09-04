from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests

from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class SupabaseAuditScanner:
    """
    Supabase-specific security checks driven by web targets.
    - Detect exposed Supabase project URLs on websites
    - Detect leaked anon/service_role keys in web content
    - Probe explicitly authorized Supabase REST/RPC roots for reachability
    """

    SUPABASE_URL_RE = re.compile(
        r"https?://[a-z0-9-]{6,}\.supabase\.(?:co|in)(?![a-z0-9.-])",
        re.IGNORECASE,
    )
    SUPABASE_HOST_RE = re.compile(
        r"^[a-z0-9-]{6,}\.supabase\.(?:co|in)$",
        re.IGNORECASE,
    )
    JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{2,}")
    KEY_ASSIGN_RE = re.compile(
        r"(?i)(supabase|anon|service(?:_role|role)?)\w*key\s*[:=]\s*['\"]([^'\"]{20,})['\"]"
    )
    RPC_CALL_RE = re.compile(r"\brpc\s*\(\s*['\"]([a-zA-Z0-9_]+)['\"]", re.IGNORECASE)
    MAX_PAGE_REQUESTS = 20
    MAX_PROBE_BASES = 12
    MAX_TOTAL_REQUESTS = MAX_PAGE_REQUESTS + (MAX_PROBE_BASES * 2)
    MAX_PAGE_CONTENT_BYTES = 2_000_000
    RESPONSE_CHUNK_BYTES = 64 * 1024

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

        resolved_timeout = resolve_timeout_seconds(timeout_seconds, default=10)

        found_supabase_urls: List[str] = []
        authorized_probe_bases: List[str] = []
        exposed_urls: List[Dict[str, str]] = []
        keys: List[Dict[str, str]] = []
        rpc_candidates: List[str] = []
        page_hits: List[Dict[str, Any]] = []
        try:
            request_page_limit = min(self.MAX_PAGE_REQUESTS, max(1, int(max_pages)))
        except (TypeError, ValueError):
            request_page_limit = 5
        request_budget = {"remaining": self.MAX_TOTAL_REQUESTS, "made": 0}

        for target in urls[:request_page_limit]:
            if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                return {"success": False, "canceled": True, "command": "supabase_audit"}

            direct_origin = self._direct_supabase_origin(target)
            if direct_origin:
                normalized = direct_origin
                if normalized not in found_supabase_urls:
                    found_supabase_urls.append(normalized)
                if normalized not in authorized_probe_bases:
                    authorized_probe_bases.append(normalized)
                exposed_urls.append({"supabase_url": normalized, "source": target})
            resp = self._streaming_get(
                target,
                timeout=resolved_timeout,
                request_budget=request_budget,
            )
            if resp is None:
                continue
            try:
                page_hits.append({"url": target, "status": resp.status_code})
                text = self._read_bounded_text(resp)
            finally:
                self._close_response(resp)
            if not text.strip():
                continue

            urls_found = list({u for u in self.SUPABASE_URL_RE.findall(text)})
            if urls_found:
                for u in urls_found:
                    normalized = self._normalize_supabase_url(u)
                    if normalized not in found_supabase_urls:
                        found_supabase_urls.append(normalized)
                    exposed_urls.append({"supabase_url": normalized, "source": target})

            extracted_keys = self._extract_keys(text)
            for key_type, key_value in extracted_keys:
                keys.append(
                    {
                        "type": key_type,
                        "value": self._mask_secret(key_value),
                        "source": target,
                    }
                )

            extracted_rpcs = self._extract_rpc_candidates(text)
            for rpc in extracted_rpcs:
                if rpc not in rpc_candidates:
                    rpc_candidates.append(rpc)

        if supabase_urls_override:
            for u in supabase_urls_override:
                normalized = self._normalize_supabase_url(u)
                if not normalized:
                    continue
                if normalized not in found_supabase_urls:
                    found_supabase_urls.append(normalized)
                if normalized not in authorized_probe_bases:
                    authorized_probe_bases.append(normalized)
                exposed_urls.append({"supabase_url": normalized, "source": "override"})

        exposures = self._probe_supabase_endpoints(
            authorized_probe_bases[: self.MAX_PROBE_BASES],
            timeout=resolved_timeout,
            cancel_event=cancel_event,
            request_budget=request_budget,
        )

        return {
            "success": True,
            "scanned": [p.get("url") for p in page_hits],
            "page_hits": page_hits,
            "supabase_urls": found_supabase_urls,
            "exposed_urls": exposed_urls,
            "keys": keys,
            "rpc_candidates": rpc_candidates,
            "rpc_probe_mode": "read_only",
            "probed_supabase_urls": authorized_probe_bases[: self.MAX_PROBE_BASES],
            "exposures": exposures,
            "request_limits": {
                "page_requests": self.MAX_PAGE_REQUESTS,
                "total_requests": self.MAX_TOTAL_REQUESTS,
                "page_content_bytes": self.MAX_PAGE_CONTENT_BYTES,
            },
            "requests_made": int(request_budget["made"]),
            "command": "supabase_audit",
        }

    def _streaming_get(
        self,
        url: str,
        *,
        timeout: int,
        request_budget: Dict[str, int],
    ):
        """Issue one bounded, non-redirecting GET without eagerly buffering its body."""

        if int(request_budget.get("remaining", 0)) <= 0:
            return None
        request_budget["remaining"] = int(request_budget["remaining"]) - 1
        request_budget["made"] = int(request_budget.get("made", 0)) + 1
        try:
            return self.session.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
        except Exception as exc:
            logger.debug(f"Supabase audit fetch failed for {url}: {exc}")
            return None

    def _read_bounded_text(self, response) -> str:
        """Read at most MAX_PAGE_CONTENT_BYTES from a streamed response."""

        remaining = self.MAX_PAGE_CONTENT_BYTES
        chunks: List[bytes] = []
        for raw_chunk in response.iter_content(
            chunk_size=self.RESPONSE_CHUNK_BYTES,
            decode_unicode=False,
        ):
            if not raw_chunk:
                continue
            chunk = raw_chunk if isinstance(raw_chunk, bytes) else str(raw_chunk).encode("utf-8")
            selected = chunk[:remaining]
            if selected:
                chunks.append(selected)
                remaining -= len(selected)
            if remaining <= 0:
                break
        encoding = str(getattr(response, "encoding", None) or "utf-8")
        try:
            return b"".join(chunks).decode(encoding, errors="replace")
        except LookupError:
            return b"".join(chunks).decode("utf-8", errors="replace")

    @staticmethod
    def _close_response(response) -> None:
        close = getattr(response, "close", None)
        if callable(close):
            close()

    def _normalize_supabase_url(self, url: str) -> str:
        """Return a canonical HTTP origin, or an empty string for invalid input."""

        try:
            parsed = urlparse(str(url or "").strip())
            scheme = str(parsed.scheme or "").lower()
            host = str(parsed.hostname or "").lower()
            port = parsed.port
        except (TypeError, ValueError):
            return ""
        if scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return ""
        display_host = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        port_suffix = f":{port}" if port is not None and port != default_port else ""
        return f"{scheme}://{display_host}{port_suffix}"

    def _direct_supabase_origin(self, target: str) -> str:
        """Authorize probing only when the target itself is a Supabase origin."""

        normalized = self._normalize_supabase_url(target)
        if not normalized:
            return ""
        try:
            host = str(urlparse(normalized).hostname or "")
        except ValueError:
            return ""
        return normalized if self.SUPABASE_HOST_RE.fullmatch(host) else ""

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
        *,
        timeout: int,
        cancel_event=None,
        request_budget: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        budget = request_budget or {"remaining": self.MAX_TOTAL_REQUESTS, "made": 0}
        exposures: List[Dict[str, Any]] = []
        for base in supabase_urls:
            if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                return exposures
            rest_url = f"{base}/rest/v1/"
            rpc_root = f"{base}/rest/v1/rpc/"
            # Root endpoints can show that a gateway is reachable, but they do
            # not prove anonymous table access or an RLS bypass.
            exposures.extend(
                self._probe_public_endpoint(rest_url, "rest_root_reachable", timeout, budget)
            )
            exposures.extend(
                self._probe_public_endpoint(rpc_root, "rpc_root_reachable", timeout, budget)
            )
        return exposures

    def _probe_public_endpoint(
        self,
        url: str,
        kind: str,
        timeout: int,
        request_budget: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        resp = self._streaming_get(url, timeout=timeout, request_budget=request_budget)
        if resp is None:
            return []
        try:
            if resp.status_code in (200, 201, 204):
                return [
                    {
                        "type": kind,
                        "url": url,
                        "status": resp.status_code,
                    }
                ]
            return []
        finally:
            self._close_response(resp)
