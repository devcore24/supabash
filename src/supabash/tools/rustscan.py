from typing import Dict, List, Any
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)


class RustscanScanner:
    """
    Wrapper for Rustscan fast port scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, ports: str = "1-1000", batch: int = 2000, arguments: str = None, cancel_event=None) -> Dict[str, Any]:
        """
        Executes a Rustscan scan against the target.

        Args:
            target (str): IP or hostname.
            ports (str): Ports or ranges (e.g., "80,443" or "1-65535").
            batch (int): Batch size to pass to nmap (-b).
            arguments (str, optional): Extra CLI arguments to append.

        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting Rustscan on {target} ports={ports} batch={batch}")

        command = [
            "rustscan",
            "-a", target,
            "-r", ports,
            "-b", str(batch),
            "--ulimit", "5000",
            "--", "--open", "-oG", "-"  # pass to nmap for greppable output
        ]

        if arguments:
            command.extend(arguments.split())

        kwargs = {"timeout": 600}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"Rustscan failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout
            }

        parsed_data = self._parse_greppable(result.stdout)
        return {
            "success": True,
            "scan_data": parsed_data,
            "command": result.command
        }

    def _parse_greppable(self, output: str) -> Dict[str, Any]:
        """
        Parses nmap greppable output (-oG -) produced by rustscan.
        Example line: Host: 192.168.0.1 () Status: Up
                      Host: 192.168.0.1 () Ports: 22/open/tcp//ssh///
        """
        hosts: Dict[str, Dict[str, Any]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("Host:"):
                continue
            if "Ports:" not in line:
                # Status line; skip unless we want it later
                continue

            # Extract IP
            try:
                host_part = line.split()[1]
            except IndexError:
                continue

            if host_part not in hosts:
                hosts[host_part] = {"ip": host_part, "ports": []}

            # Extract port entries
            if "Ports:" in line:
                ports_section = line.split("Ports:")[1].strip()
                for port_entry in ports_section.split(","):
                    port_entry = port_entry.strip()
                    if not port_entry:
                        continue
                    parts = port_entry.split("/")
                    if len(parts) < 5:
                        continue
                    port, state, proto, _, service = parts[:5]
                    if state != "open":
                        continue
                    try:
                        port_num = int(port)
                    except ValueError:
                        logger.debug(f"Skipping non-numeric port entry: {port_entry}")
                        continue

                    hosts[host_part]["ports"].append({
                        "port": port_num,
                        "protocol": proto,
                        "state": state,
                        "service": service or "unknown"
                    })

        return {"hosts": list(hosts.values())}
