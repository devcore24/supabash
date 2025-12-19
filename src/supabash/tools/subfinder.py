import json
from typing import Any, Dict, List, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds


logger = setup_logger(__name__)


class SubfinderScanner:
    """
    Wrapper for ProjectDiscovery subfinder (subdomain discovery).

    Notes:
    - Uses JSONL output for reliable parsing (`-json`).
    - Many sources require API keys; results may be limited without provider config.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        domain: str,
        *,
        silent: bool = True,
        jsonl: bool = True,
        collect_sources: bool = False,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        d = (domain or "").strip()
        if not d:
            return {"success": False, "error": "No domain provided", "command": ""}

        command = ["subfinder", "-d", d]
        if silent:
            command.append("-silent")
        if jsonl:
            command.append("-json")
        if collect_sources:
            command.append("-collect-sources")

        timeout = resolve_timeout_seconds(timeout_seconds, default=600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        logger.info(f"Starting subfinder scan on {d}")
        result: CommandResult = self.runner.run(command, **kwargs)
        if not result.success:
            err = result.stderr or result.stdout or f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
            }

        hosts = self._parse_hosts(result.stdout, jsonl=jsonl)
        return {
            "success": True,
            "domain": d,
            "hosts": hosts,
            "findings": hosts,
            "command": result.command,
        }

    def _parse_hosts(self, output: str, *, jsonl: bool) -> List[str]:
        s = (output or "").strip()
        if not s:
            return []

        if not jsonl:
            return [line.strip() for line in s.splitlines() if line.strip()]

        hosts: List[str] = []
        for line in s.splitlines():
            line = (line or "").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    host = obj.get("host") or obj.get("Host")
                    if host and str(host).strip():
                        hosts.append(str(host).strip())
                        continue
            except Exception:
                pass
            # Fallback: subfinder may emit plain lines under some conditions
            if "." in line and " " not in line and "\t" not in line:
                hosts.append(line)
        # Preserve order while deduping
        seen = set()
        out_hosts: List[str] = []
        for h in hosts:
            if h not in seen:
                out_hosts.append(h)
                seen.add(h)
        return out_hosts

