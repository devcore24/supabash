from typing import Dict, Any, Optional
import os
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class HydraRunner:
    """
    Wrapper for Hydra password brute-forcing.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def run(
        self,
        target: str,
        service: str,
        usernames: str,
        passwords: str,
        options: str = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a Hydra brute-force attempt.

        Args:
            target (str): Target host/IP (optionally host:port).
            service (str): Service module (e.g., ssh, ftp, http-get).
            usernames (str): Path to usernames file or single username.
            passwords (str): Path to passwords file or single password.
            options (str, optional): Extra Hydra CLI options.

        Returns:
            Dict: Result with success flag and raw output.
        """
        logger.info(f"Starting Hydra against {service}://{target}")

        user_flag = "-L" if ("/" in usernames or usernames.endswith((".txt", ".lst"))) else "-l"
        pass_flag = "-P" if ("/" in passwords or passwords.endswith((".txt", ".lst"))) else "-p"

        command = [
            "hydra",
            user_flag,
            usernames,
            pass_flag,
            passwords,
            service + "://" + target,
            "-o",
            "/tmp/hydra.out",
        ]

        if options:
            command[1:1] = options.split()

        timeout = resolve_timeout_seconds(timeout_seconds, default=3600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"Hydra failed: {result.stderr}")
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

        return {"success": True, "raw_output": result.stdout, "command": result.command}
