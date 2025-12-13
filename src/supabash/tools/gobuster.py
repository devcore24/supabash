from typing import Dict, List, Any, Optional
from pathlib import Path
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger

logger = setup_logger(__name__)

class GobusterScanner:
    """
    Wrapper for Gobuster Directory Scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        target: str,
        wordlist: Optional[str] = None,
        threads: int = 10,
        cancel_event=None,
    ) -> Dict[str, Any]:
        """
        Executes a Gobuster scan against the target.
        
        Args:
            target (str): Target URL (must include http/https).
            wordlist (str): Path to wordlist.
            threads (int): Number of concurrent threads.
            
        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting Gobuster scan on {target}")

        if not wordlist:
            system = Path("/usr/share/wordlists/dirb/common.txt")
            if system.exists():
                wordlist = str(system)
            else:
                fallback = Path(__file__).resolve().parents[1] / "data" / "wordlists" / "common.txt"
                wordlist = str(fallback)
        
        # Command: gobuster dir -u <target> -w <wordlist> -q -z --no-error
        # -q: Quiet mode (only findings)
        # -z: No progress bar
        # --no-error: Don't exit on error
        command = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "-q",
            "-z",
            "--no-error"
        ]

        # 30 minute timeout
        kwargs = {"timeout": 1800}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"Gobuster scan failed: {result.stderr}")
            err = result.stderr
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout
            }

        parsed_data = self._parse_output(result.stdout)
        return {
            "success": True,
            "findings": parsed_data,
            "command": result.command
        }

    def _parse_output(self, output: str) -> List[str]:
        """
        Parses Gobuster text output.
        Gobuster output format (quiet):
        /admin (Status: 301) [Size: 123]
        """
        findings = []
        if not output.strip():
            return findings

        for line in output.splitlines():
            if line.strip():
                findings.append(line.strip())
        
        return findings
