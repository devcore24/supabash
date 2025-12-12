import json
from typing import Dict, Any, List
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)


class TrivyScanner:
    """
    Wrapper for Trivy container image scanning.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, image: str, severity: str = "HIGH,CRITICAL", arguments: str = None, cancel_event=None) -> Dict[str, Any]:
        """
        Run Trivy against a container image and return parsed JSON results.

        Args:
            image (str): Image name/tag.
            severity (str): Comma-separated severities to include.
            arguments (str, optional): Extra CLI args.
        """
        logger.info(f"Starting Trivy scan on {image}")

        command = [
            "trivy",
            "image",
            "--format",
            "json",
            "--severity",
            severity,
            image,
        ]

        if arguments:
            command.extend(arguments.split())

        kwargs = {"timeout": 1800}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"Trivy scan failed: {result.stderr}")
            return {"success": False, "error": result.stderr, "canceled": bool(getattr(result, "canceled", False)), "raw_output": result.stdout}

        parsed = self._parse_json(result.stdout)
        return {"success": True, "findings": parsed, "command": result.command}

    def _parse_json(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Trivy JSON output; return summarized vulnerabilities list.
        """
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.debug("Failed to parse Trivy JSON output")
            return []

        findings = []
        results = data if isinstance(data, list) else data.get("Results", [])
        for res in results:
            vulns = res.get("Vulnerabilities") or []
            target = res.get("Target")
            for v in vulns:
                findings.append(
                    {
                        "target": target,
                        "id": v.get("VulnerabilityID"),
                        "pkg": v.get("PkgName"),
                        "severity": v.get("Severity"),
                        "title": v.get("Title"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                    }
                )
        return findings
