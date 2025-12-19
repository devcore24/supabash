import json
from typing import Any, Dict, List, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds


logger = setup_logger(__name__)


class KatanaScanner:
    """
    Wrapper for ProjectDiscovery katana (crawler/spider).

    Notes:
    - Uses JSONL output (`-jsonl`) for structured parsing.
    - Intended for endpoint discovery (non-bruteforce) and attack-surface mapping.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def crawl(
        self,
        target_url: str,
        *,
        depth: int = 3,
        concurrency: int = 10,
        silent: bool = True,
        jsonl: bool = True,
        tech_detect: bool = False,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        u = (target_url or "").strip()
        if not u:
            return {"success": False, "error": "No target URL provided", "command": ""}
        if not u.startswith(("http://", "https://")):
            return {"success": False, "error": "Target must include http:// or https://", "command": ""}

        command = [
            "katana",
            "-u",
            u,
            "-depth",
            str(max(1, int(depth))),
            "-concurrency",
            str(max(1, int(concurrency))),
        ]
        if tech_detect:
            command.append("-tech-detect")
        if silent:
            command.append("-silent")
        if jsonl:
            command.append("-jsonl")

        timeout = resolve_timeout_seconds(timeout_seconds, default=1800)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        logger.info(f"Starting katana crawl on {u}")
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

        urls = self._parse_urls(result.stdout, jsonl=jsonl)
        return {
            "success": True,
            "target": u,
            "urls": urls,
            "findings": urls,
            "command": result.command,
        }

    def _parse_urls(self, output: str, *, jsonl: bool) -> List[str]:
        s = (output or "").strip()
        if not s:
            return []

        urls: List[str] = []
        for line in s.splitlines():
            line = (line or "").strip()
            if not line:
                continue

            if jsonl:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        # Most reliable: request.endpoint
                        req = obj.get("request")
                        if isinstance(req, dict):
                            ep = req.get("endpoint")
                            if ep and str(ep).strip():
                                urls.append(str(ep).strip())
                                continue
                        # Fall back to common fields
                        for key in ("url", "URL", "endpoint"):
                            v = obj.get(key)
                            if v and str(v).strip():
                                urls.append(str(v).strip())
                                break
                        else:
                            continue
                    else:
                        continue
                except Exception:
                    # fall through to plaintext heuristic
                    pass

            if line.startswith(("http://", "https://")):
                urls.append(line)

        # Preserve order while deduping
        seen = set()
        out_urls: List[str] = []
        for u in urls:
            if u not in seen:
                out_urls.append(u)
                seen.add(u)
        return out_urls

