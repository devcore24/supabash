import json
from typing import Dict, List, Any
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)

class NucleiScanner:
    """
    Wrapper for Nuclei Vulnerability Scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, templates: str = None, rate_limit: int = None, cancel_event=None) -> Dict[str, Any]:
        """
        Executes a Nuclei scan against the target.
        
        Args:
            target (str): IP or hostname.
            templates (str, optional): Specific templates to run (e.g., "cves", "technologies").
            rate_limit (int, optional): Requests per second limit.
            
        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting Nuclei scan on {target}")
        
        # Command: nuclei -target <target> -json -silent
        command = [
            "nuclei",
            "-target", target,
            "-json",
            "-silent"
        ]

        if templates:
            command.extend(["-t", templates])
        if rate_limit:
            command.extend(["-rate-limit", str(rate_limit)])

        # Nuclei can take a while depending on templates, default 30 min
        kwargs = {"timeout": 1800}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"Nuclei scan failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout
            }

        parsed_data = self._parse_json(result.stdout)
        return {
            "success": True,
            "findings": parsed_data,
            "command": result.command
        }

    def _parse_json(self, json_content: str) -> List[Dict[str, Any]]:
        """
        Parses Nuclei JSON-L output.
        """
        findings = []
        if not json_content.strip():
            return findings

        for line in json_content.splitlines():
            try:
                if not line.strip():
                    continue
                finding = json.loads(line)
                
                # Simplify finding structure
                simplified = {
                    "id": finding.get("template-id"),
                    "name": finding.get("info", {}).get("name"),
                    "severity": finding.get("info", {}).get("severity"),
                    "type": finding.get("type"),
                    "host": finding.get("host"),
                    "matched_at": finding.get("matched-at"),
                    "description": finding.get("info", {}).get("description", "")
                }
                findings.append(simplified)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Nuclei JSON line: {e}")
        
        return findings
