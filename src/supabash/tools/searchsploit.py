import json
from typing import Any, Dict, List, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds


logger = setup_logger(__name__)


class SearchsploitScanner:
    """
    Wrapper for Searchsploit (Exploit-DB offline search).

    This is a *reference* tool: it suggests relevant public exploit PoCs
    based on service banners/version strings. It does not validate or exploit.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def search(
        self,
        query: str,
        *,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        q = (query or "").strip()
        if not q:
            return {"success": False, "error": "No query provided", "command": ""}

        command = ["searchsploit", "-j", q]

        timeout = resolve_timeout_seconds(timeout_seconds, default=60)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        result: CommandResult = self.runner.run(command, **kwargs)
        if not result.success:
            err = result.stderr
            if not err:
                err = result.stdout or ""
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
            }

        parsed = self._parse_json(result.stdout)
        findings = self._to_findings(parsed)
        return {
            "success": True,
            "query": q,
            "findings": findings,
            "results": parsed,
            "command": result.command,
        }

    def _parse_json(self, output: str) -> Dict[str, Any]:
        s = (output or "").strip()
        if not s:
            return {}
        try:
            obj = json.loads(s)
            return obj if isinstance(obj, dict) else {}
        except Exception as e:
            logger.debug(f"Failed to parse searchsploit JSON: {e}")
            return {}

    def _to_findings(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(obj, dict):
            return findings

        results = obj.get("RESULTS_EXPLOIT", []) or []
        if isinstance(results, dict):
            results = results.get("exploits", []) or []
        if not isinstance(results, list):
            results = []

        shellcodes = obj.get("RESULTS_SHELLCODE", []) or []
        if isinstance(shellcodes, dict):
            shellcodes = shellcodes.get("shellcodes", []) or []
        if not isinstance(shellcodes, list):
            shellcodes = []

        def add(items: List[Any], kind: str):
            for it in items:
                if not isinstance(it, dict):
                    continue
                title = it.get("Title") or it.get("title") or ""
                path = it.get("Path") or it.get("path") or ""
                if not title and not path:
                    continue
                findings.append(
                    {
                        "kind": kind,
                        "title": str(title),
                        "path": str(path),
                    }
                )

        add(results, "exploit")
        add(shellcodes, "shellcode")
        return findings

