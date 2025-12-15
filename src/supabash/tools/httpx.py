import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class HttpxScanner:
    """
    Wrapper for ProjectDiscovery httpx (HTTP probing / service enumeration).
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        targets: Union[str, Sequence[str]],
        *,
        threads: int = 50,
        follow_redirects: bool = True,
        timeout_seconds: Optional[int] = None,
        cancel_event=None,
    ) -> Dict[str, Any]:
        inputs: List[str] = []
        if isinstance(targets, str):
            t = targets.strip()
            if t:
                inputs = [t]
        else:
            inputs = [str(x).strip() for x in list(targets or []) if str(x).strip()]

        if not inputs:
            return {"success": False, "error": "No targets provided", "command": ""}

        # httpx supports -l for input list; easiest way to probe multiple URLs.
        tmpdir = Path(tempfile.mkdtemp(prefix="supabash-httpx-"))
        input_file = tmpdir / "targets.txt"
        input_file.write_text("\n".join(inputs) + "\n", encoding="utf-8")

        command = [
            "httpx",
            "-silent",
            "-json",
            "-l",
            str(input_file),
            "-threads",
            str(max(1, int(threads))),
            "-timeout",
            "5",
            "-retries",
            "1",
            "-status-code",
            "-title",
            "-web-server",
            "-tech-detect",
        ]
        if follow_redirects:
            command.append("-follow-redirects")

        timeout = resolve_timeout_seconds(timeout_seconds, default=300)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        result: CommandResult = self.runner.run(command, **kwargs)

        # Cleanup tempdir
        try:
            input_file.unlink(missing_ok=True)
            tmpdir.rmdir()
        except Exception:
            pass

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

        entries = self._parse_json_lines(result.stdout)
        alive = [e.get("url") for e in entries if isinstance(e, dict) and isinstance(e.get("url"), str) and e.get("url")]
        return {
            "success": True,
            "probed": inputs,
            "alive": alive,
            "results": entries,
            "command": result.command,
        }

    def _parse_json_lines(self, output: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for line in (output or "").splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
                if not isinstance(obj, dict):
                    continue
                items.append(obj)
            except json.JSONDecodeError:
                logger.debug(f"Skipping invalid JSON line from httpx: {s[:120]}")
        return items

