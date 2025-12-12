import json
from typing import Dict, List, Any
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)


class WhatWebScanner:
    """
    Wrapper for WhatWeb technology detection.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, arguments: str = None, cancel_event=None) -> Dict[str, Any]:
        """
        Executes a WhatWeb scan against the target.

        Args:
            target (str): URL or host to scan.
            arguments (str, optional): Additional WhatWeb CLI arguments.

        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting WhatWeb on {target}")

        command = ["whatweb", target, "--log-json", "-"]
        if arguments:
            command.extend(arguments.split())

        kwargs = {"timeout": 300}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"WhatWeb scan failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout
            }

        parsed = self._parse_json_lines(result.stdout)
        return {
            "success": True,
            "scan_data": parsed,
            "command": result.command
        }

    def _parse_json_lines(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse WhatWeb JSON-lines output.
        """
        findings = []
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "target": data.get("target"),
                    "plugins": data.get("plugins", {}),
                    "banner": data.get("banner"),
                    "status": data.get("http_status"),
                })
            except json.JSONDecodeError:
                logger.debug(f"Skipping invalid JSON line from WhatWeb: {line}")
        return findings
