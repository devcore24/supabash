from typing import Any, Dict, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class Enum4linuxNgScanner:
    """
    Wrapper for enum4linux-ng (SMB enumeration).

    Note: output is primarily text; this wrapper stores raw output for reporting.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        target: str,
        arguments: str = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        target = (target or "").strip()
        if not target:
            return {"success": False, "error": "Missing target"}

        logger.info(f"Starting enum4linux-ng on {target}")

        command = ["enum4linux-ng", "-A", target]
        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=1200)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            err = result.stderr or result.stdout
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
            }

        return {
            "success": True,
            "raw_output": result.stdout,
            "command": result.command,
        }
