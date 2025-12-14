from typing import Dict, Any, Optional
import requests
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class SupabaseRLSChecker:
    """
    Simple checker to detect missing Row Level Security (RLS) on Supabase endpoints.
    Heuristic: if the endpoint responds 200/201 without auth, we flag RLS as potentially disabled.
    """

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def check(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        logger.info(f"Checking Supabase RLS for {url}")
        command = f"HTTP GET {url}"
        resolved_timeout = resolve_timeout_seconds(timeout_seconds, default=timeout)
        try:
            resp = self.session.get(url, headers=headers, timeout=resolved_timeout)
        except Exception as e:
            logger.error(f"Supabase RLS check failed: {e}")
            return {"success": False, "error": str(e), "command": command}

        status = resp.status_code
        rls_enabled = status in (401, 403)
        risk = not rls_enabled and status < 500

        return {
            "success": True,
            "status": status,
            "rls_enabled": rls_enabled,
            "risk": risk,
            "url": url,
            "command": command,
        }
