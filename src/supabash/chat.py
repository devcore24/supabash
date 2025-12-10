import json
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    MasscanScanner,
    RustscanScanner,
)

logger = setup_logger(__name__)


@dataclass
class ChatSession:
    scanners: Dict[str, Any] = field(default_factory=lambda: {
        "nmap": NmapScanner(),
        "masscan": MasscanScanner(),
        "rustscan": RustscanScanner(),
    })
    last_scan_result: Optional[Dict[str, Any]] = None
    last_scan_tool: Optional[str] = None

    def run_scan(self, target: str, profile: str = "fast", scanner_name: str = "nmap") -> Dict[str, Any]:
        scanner_name = scanner_name.lower()
        if scanner_name not in self.scanners:
            return {"success": False, "error": f"Unknown scanner '{scanner_name}'"}

        scanner = self.scanners[scanner_name]
        ports = None
        args = None
        extra = {}

        if scanner_name == "nmap":
            args = "-sV -O"
            if profile == "fast":
                args += " -F"
            elif profile == "full":
                ports = "1-65535"
                args += " -T4"
            elif profile == "stealth":
                args = "-sS -T2"
            result = scanner.scan(target, ports=ports, arguments=args)
        elif scanner_name == "masscan":
            ports = "1-1000"
            rate = 1000
            if profile == "full":
                ports = "1-65535"
                rate = 5000
            elif profile == "stealth":
                rate = 100
            result = scanner.scan(target, ports=ports, rate=rate, arguments=args)
        else:  # rustscan
            ports = "1-1000"
            batch = 2000
            if profile == "full":
                ports = "1-65535"
                batch = 5000
            elif profile == "stealth":
                batch = 1000
            result = scanner.scan(target, ports=ports, batch=batch, arguments=args)

        self.last_scan_result = result
        self.last_scan_tool = scanner_name
        return result

    def save_report(self, path: Path) -> Dict[str, Any]:
        if not self.last_scan_result:
            return {"success": False, "error": "No scan results to save."}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(self.last_scan_result, f, indent=2)
            return {"success": True, "path": str(path)}
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return {"success": False, "error": str(e)}

    def run_tests(self, workdir: Optional[Path] = None) -> Dict[str, Any]:
        cmd = [self._python_executable(), "-m", "unittest", "discover", "-s", "tests"]
        try:
            result = subprocess.run(
                cmd,
                cwd=str(workdir) if workdir else None,
                capture_output=True,
                text=True,
                timeout=900,
            )
            return {
                "success": result.returncode == 0,
                "return_code": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        except Exception as e:
            logger.error(f"Failed to run tests: {e}")
            return {"success": False, "error": str(e)}

    def _python_executable(self) -> str:
        return subprocess.run(
            ["which", "python"],
            capture_output=True,
            text=True,
        ).stdout.strip() or "python"
