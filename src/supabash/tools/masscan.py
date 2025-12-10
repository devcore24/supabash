from typing import Dict, List, Any
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)

class MasscanScanner:
    """
    Wrapper for Masscan high-speed port scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, ports: str = "1-1000", rate: int = 1000, arguments: str = None) -> Dict[str, Any]:
        """
        Executes a Masscan scan against the target.

        Args:
            target (str): IP or CIDR to scan.
            ports (str): Ports or ranges (e.g., "80,443" or "1-65535").
            rate (int): Packets per second rate limit.
            arguments (str, optional): Extra CLI arguments to append.

        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting Masscan scan on {target} ports={ports} rate={rate}")

        command = [
            "masscan",
            target,
            "-p", ports,
            "--rate", str(rate),
            "-oL", "-"  # list output to stdout for parsing
        ]

        if arguments:
            command.extend(arguments.split())

        result: CommandResult = self.runner.run(command, timeout=600)

        if not result.success:
            logger.error(f"Masscan scan failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "raw_output": result.stdout
            }

        parsed_data = self._parse_list_output(result.stdout)
        return {
            "success": True,
            "scan_data": parsed_data,
            "command": result.command
        }

    def _parse_list_output(self, output: str) -> Dict[str, Any]:
        """
        Parses Masscan list output (-oL) into a structured dict.
        Expected line format: 'open tcp 80 192.168.0.1 0.123s'
        """
        hosts: Dict[str, Dict[str, Any]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            status, proto, port, ip = parts[:4]
            if status.lower() != "open":
                continue

            try:
                port_num = int(port)
            except ValueError:
                logger.debug(f"Skipping non-numeric port entry: {port}")
                continue

            if ip not in hosts:
                hosts[ip] = {"ip": ip, "ports": []}

            hosts[ip]["ports"].append({
                "port": port_num,
                "protocol": proto.lower(),
                "state": status.lower()
            })

        return {"hosts": list(hosts.values())}
