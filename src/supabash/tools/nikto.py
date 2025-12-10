import xml.etree.ElementTree as ET
from typing import Dict, List, Any
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)

class NiktoScanner:
    """
    Wrapper for Nikto Web Server Scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, port: int = 80) -> Dict[str, Any]:
        """
        Executes a Nikto scan against the target.
        
        Args:
            target (str): IP or hostname.
            port (int): Port to scan (default 80).
            
        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting Nikto scan on {target}:{port}")
        
        # Command: nikto -h <target> -p <port> -Format xml -o -
        command = [
            "nikto",
            "-h", target,
            "-p", str(port),
            "-Format", "xml",
            "-o", "-"
        ]

        # Nikto can take a while, 20 min timeout
        result: CommandResult = self.runner.run(command, timeout=1200)

        if not result.success:
            logger.error(f"Nikto scan failed: {result.stderr}")
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
        Parses Nikto XML output into a simplified dictionary.
        """
        try:
            # Nikto output sometimes contains header text before the XML.
            # We need to strip that or find the start of XML.
            if "<?xml" not in xml_content and "<niktoscan" in xml_content:
                # Try to parse partial XML or just find the root
                start = xml_content.find("<niktoscan")
                if start != -1:
                    xml_content = xml_content[start:]
            
            # Simple check for empty output
            if not xml_content.strip():
                 return {"findings": []}

            root = ET.fromstring(xml_content)
            scan_result = {
                "target_ip": "",
                "target_hostname": "",
                "target_port": "",
                "banner": "",
                "findings": []
            }

            scandetails = root.find("scandetails")
            if scandetails is not None:
                scan_result["target_ip"] = scandetails.get("targetip")
                scan_result["target_hostname"] = scandetails.get("targethostname")
                scan_result["target_port"] = scandetails.get("targetport")
                scan_result["banner"] = scandetails.get("sitename") # Sometimes banner is here or in first item

                for item in scandetails.findall("item"):
                    finding = {
                        "id": item.get("id"),
                        "osvdb": item.get("osvdbid"),
                        "method": item.get("method"),
                        "description": ""
                    }
                    
                    desc_el = item.find("description")
                    if desc_el is not None:
                        finding["description"] = desc_el.text
                    
                    uri_el = item.find("uri")
                    if uri_el is not None:
                        finding["uri"] = uri_el.text

                    scan_result["findings"].append(finding)

            return scan_result

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nikto XML: {e}")
            # Fallback: Return raw output if parsing fails? 
            # Or just empty findings with error note.
            return {"error": "XML Parse Error", "details": str(e)}
