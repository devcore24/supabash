import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds


logger = setup_logger(__name__)


class FfufScanner:
    """
    Wrapper for ffuf (Fast web fuzzer) for content discovery.

    Notes:
    - Uses auto-calibration (-ac) by default to handle wildcard/soft-404 behavior.
    - Outputs JSON to stdout (-o -) for easy parsing.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        target: str,
        *,
        wordlist: Optional[str] = None,
        threads: int = 20,
        auto_calibrate: bool = True,
        matcher_codes: str = "200,204,301,302,307,401,403",
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        logger.info(f"Starting ffuf scan on {target}")

        if not isinstance(target, str) or not target.strip():
            return {"success": False, "error": "No target provided", "command": ""}

        base = target.strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            return {"success": False, "error": "Target must include http:// or https://", "command": ""}

        if not wordlist:
            system = Path("/usr/share/wordlists/dirb/common.txt")
            if system.exists():
                wordlist = str(system)
            else:
                fallback = Path(__file__).resolve().parents[1] / "data" / "wordlists" / "common.txt"
                wordlist = str(fallback)

        url = f"{base}/FUZZ"
        command = [
            "ffuf",
            "-u",
            url,
            "-w",
            str(wordlist),
            "-t",
            str(max(1, int(threads))),
            "-of",
            "json",
            "-o",
            "-",
            "-mc",
            str(matcher_codes),
        ]
        if auto_calibrate:
            command.append("-ac")

        timeout = resolve_timeout_seconds(timeout_seconds, default=1800)
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
            "findings": findings,
            "results": parsed,
            "command": result.command,
        }

    def _parse_json(self, output: str) -> Dict[str, Any]:
        s = (output or "").strip()
        if not s:
            return {"results": []}
        try:
            obj = json.loads(s)
            return obj if isinstance(obj, dict) else {"results": []}
        except Exception as e:
            logger.debug(f"Failed to parse ffuf JSON: {e}")
            return {"results": []}

    def _to_findings(self, obj: Dict[str, Any]) -> List[str]:
        results = obj.get("results", []) if isinstance(obj, dict) else []
        if not isinstance(results, list):
            return []
        findings: List[str] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            url = r.get("url") or r.get("redirectlocation") or ""
            status = r.get("status")
            length = r.get("length")
            if not url:
                continue
            parts = [str(url)]
            if status is not None:
                parts.append(f"(Status: {status})")
            if length is not None:
                parts.append(f"[Size: {length}]")
            findings.append(" ".join(parts))
        return findings

