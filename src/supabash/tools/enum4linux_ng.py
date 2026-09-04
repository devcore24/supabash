from typing import Any, Dict, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds
from supabash.tool_registry import resolve_tool_executable

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

        executable = resolve_tool_executable("enum4linux_ng", require_healthy=True)
        self.last_executable = executable
        if not executable:
            return {
                "success": False,
                "error": "No compatible enum4linux executable was found",
                "command": "",
            }

        command = [executable, "-A", target]
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
            "executable": executable,
        }
