import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)

class NmapScanner:
    """
    Wrapper for Nmap Security Scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, ports: str = None, arguments: str = "-sV -O") -> Dict[str, Any]:
        """
        Executes an Nmap scan against the target.
        
        Args:
            target (str): IP or hostname.
            ports (str, optional): Ports to scan (e.g., "80,443" or "1-1000").
            arguments (str): Additional Nmap arguments (default: Service & OS detection).
            
        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting Nmap scan on {target}")
        
        # Construct command
        # We always use -oX - to output XML to stdout for parsing
        command = ["nmap", target, "-oX", "-"]
        
        if ports:
            command.extend(["-p", ports])
            
        if arguments:
            # simple split, might need more robust shlex split if args contain quotes
            command.extend(arguments.split())

        result: CommandResult = self.runner.run(command, timeout=600) # 10 min timeout default

        if not result.success:
            logger.error(f"Nmap scan failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "raw_output": result.stdout
            }

        parsed_data = self._parse_xml(result.stdout)
        return {
            "success": True,
            "scan_data": parsed_data,
            "command": result.command
        }

    def _parse_xml(self, xml_content: str) -> Dict[str, Any]:
        """
        Parses Nmap XML output into a simplified dictionary.
        """
        try:
            root = ET.fromstring(xml_content)
            scan_result = {
                "hosts": []
            }

            for host in root.findall("host"):
                host_data = {
                    "ip": "",
                    "hostnames": [],
                    "ports": [],
                    "os": []
                }

                # Get IP Address
                address = host.find("address")
                if address is not None:
                    host_data["ip"] = address.get("addr")

                # Get Hostnames
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hn in hostnames.findall("hostname"):
                        host_data["hostnames"].append(hn.get("name"))

                # Get Ports & Services
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        
                        state_el = port.find("state")
                        state = state_el.get("state") if state_el is not None else "unknown"
                        
                        # Only keep open ports
                        if state != "open":
                            continue

                        service_el = port.find("service")
                        service_name = service_el.get("name") if service_el is not None else "unknown"
                        product = service_el.get("product", "") if service_el is not None else ""
                        version = service_el.get("version", "") if service_el is not None else ""

                        host_data["ports"].append({
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": state,
                            "service": service_name,
                            "product": product,
                            "version": version
                        })

                # Get OS Match
                os_el = host.find("os")
                if os_el is not None:
                    for os_match in os_el.findall("osmatch"):
                        host_data["os"].append({
                            "name": os_match.get("name"),
                            "accuracy": os_match.get("accuracy")
                        })

                scan_result["hosts"].append(host_data)

            return scan_result

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {"error": "XML Parse Error", "details": str(e)}
