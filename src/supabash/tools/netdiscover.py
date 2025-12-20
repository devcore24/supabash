import re
from typing import Dict, List, Any, Optional
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class NetdiscoverScanner:
    """
    Wrapper for Netdiscover ARP reconnaissance tool.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        interface: Optional[str] = None,
        range: Optional[str] = None,
        passive: bool = False,
        fast_mode: bool = True,
        arguments: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a Netdiscover scan for ARP-based host discovery.

        Args:
            interface (str, optional): Network interface to use (e.g., 'eth0').
            range (str, optional): IP range to scan (e.g., '192.168.1.0/24').
            passive (bool): Passive mode (sniff only, don't send ARP requests).
            fast_mode (bool): Fast mode (send ARP requests quickly).
            arguments (str, optional): Additional CLI arguments.

        Returns:
            Dict: Parsed scan results with discovered hosts.
        """
        logger.info(f"Starting Netdiscover{' on ' + range if range else ''}")

        # Netdiscover requires root privileges
        command = ["netdiscover", "-P"]  # -P for parseable output

        if interface:
            command.extend(["-i", interface])

        if range:
            command.extend(["-r", range])

        if passive:
            command.append("-p")

        if fast_mode and not passive:
            command.append("-f")

        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=300)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        # Netdiscover may exit with non-zero even on success (timeout-based)
        # So we check if we got output rather than just success status
        has_output = bool(result.stdout and result.stdout.strip())

        if not result.success and not has_output:
            logger.error(f"Netdiscover failed: {result.stderr}")
            err = result.stderr
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
            }

        parsed = self._parse_output(result.stdout)
        return {
            "success": True,
            "scan_data": parsed,
            "command": result.command,
        }

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Netdiscover parseable output.

        Format (with -P flag):
        IP            MAC Address      Count  Len   Vendor
        192.168.1.1   aa:bb:cc:dd:ee:ff    1   60   Vendor Name
        """
        result = {
            "hosts": [],
            "total_hosts": 0,
        }

        if not output:
            return result

        lines = output.strip().splitlines()

        # Pattern for parseable output line
        # IP / MAC / Count / Len / Vendor (vendor may contain spaces)
        pattern = re.compile(
            r'^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+'
            r'(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+'
            r'(?P<count>\d+)\s+'
            r'(?P<len>\d+)\s*'
            r'(?P<vendor>.*)$'
        )

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Skip header lines
            if line_stripped.startswith('IP') or line_stripped.startswith('---'):
                continue

            match = pattern.match(line_stripped)
            if match:
                host = {
                    "ip": match.group("ip"),
                    "mac": match.group("mac").lower(),
                    "count": int(match.group("count")),
                    "len": int(match.group("len")),
                    "vendor": match.group("vendor").strip() or "Unknown",
                }
                result["hosts"].append(host)

        result["total_hosts"] = len(result["hosts"])
        return result

    def scan_range(
        self,
        cidr: str,
        interface: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method to scan a CIDR range.

        Args:
            cidr (str): CIDR notation (e.g., '192.168.1.0/24').
            interface (str, optional): Network interface.

        Returns:
            Dict: Scan results.
        """
        return self.scan(
            interface=interface,
            range=cidr,
            passive=False,
            fast_mode=True,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )
