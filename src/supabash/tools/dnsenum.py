import re
from typing import Any, Dict, List, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class DnsenumScanner:
    """
    Wrapper for dnsenum (DNS enumeration).
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        domain: str,
        arguments: str = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        domain = (domain or "").strip()
        if not domain:
            return {"success": False, "error": "Missing domain"}

        logger.info(f"Starting dnsenum on {domain}")

        command = ["dnsenum", domain]
        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=900)
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

        parsed = self._parse_hosts(result.stdout)
        return {
            "success": True,
            "scan_data": parsed,
            "raw_output": result.stdout,
            "command": result.command,
        }

    def _parse_hosts(self, output: str) -> Dict[str, Any]:
        """
        Best-effort extraction of host->ip mappings from dnsenum output.
        """
        output = output or ""
        hosts: List[Dict[str, Any]] = []
        ips: List[str] = []

        # Common patterns:
        #   www.example.com.  93.184.216.34
        #   mail.example.com  93.184.216.34
        host_ip_re = re.compile(r"^([a-zA-Z0-9._-]+)\.?\s+((?:\d{1,3}\.){3}\d{1,3})\b")
        for line in output.splitlines():
            line = line.strip()
            m = host_ip_re.match(line)
            if not m:
                continue
            host = m.group(1).rstrip(".")
            ip = m.group(2)
            hosts.append({"host": host, "ip": ip})
            ips.append(ip)

        uniq_ips = sorted(set(ips))
        return {"hosts": hosts, "ips": uniq_ips}
