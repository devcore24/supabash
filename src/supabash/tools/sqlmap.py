import json
from typing import Dict, Any, List
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)


class SqlmapScanner:
    """
    Wrapper for sqlmap (automated SQL injection detection).
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(self, target: str, arguments: str = None, output_dir: str = None) -> Dict[str, Any]:
        """
        Run sqlmap against a target URL.

        Args:
            target (str): Target URL with parameters.
            arguments (str, optional): Extra sqlmap CLI args.
            output_dir (str, optional): Custom output directory.

        Returns:
            Dict: Result including parsed findings if available.
        """
        logger.info(f"Starting sqlmap on {target}")

        command = ["sqlmap", "-u", target, "--batch", "--disable-coloring", "--output-dir=/tmp/sqlmap"]

        if output_dir:
            command[-1] = f"--output-dir={output_dir}"

        if arguments:
            command.extend(arguments.split())

        result: CommandResult = self.runner.run(command, timeout=1800)

        if not result.success:
            logger.error(f"sqlmap failed: {result.stderr}")
            return {"success": False, "error": result.stderr, "raw_output": result.stdout}

        parsed = self._parse_output(result.stdout)
        return {"success": True, "findings": parsed, "command": result.command}

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Minimal parser for sqlmap stdout:
        - Detects parameter vulnerability lines like "[INFO] GET parameter 'id' appears to be 'UNION query' injectable"
        """
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if "appears to be" in line and "injectable" in line:
                findings.append({"detail": line})
        return findings
