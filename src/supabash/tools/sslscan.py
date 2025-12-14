import re
from typing import Any, Dict, List, Optional

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class SslscanScanner:
    """
    Wrapper for sslscan TLS configuration checks.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        host: str,
        port: int = 443,
        arguments: str = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        host = (host or "").strip()
        if not host:
            return {"success": False, "error": "Missing host"}
        try:
            port = int(port)
        except Exception:
            return {"success": False, "error": f"Invalid port: {port}"}

        target = f"{host}:{port}"
        logger.info(f"Starting sslscan on {target}")

        command = ["sslscan", "--no-colour", target]
        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            err = result.stderr or result.stdout
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
            }

        parsed = self._parse_summary(result.stdout)
        return {
            "success": True,
            "scan_data": parsed,
            "raw_output": result.stdout,
            "command": result.command,
        }

    def _parse_summary(self, output: str) -> Dict[str, Any]:
        """
        Best-effort summary extraction from sslscan text output.
        """
        output = output or ""
        protocols: List[Dict[str, Any]] = []

        # Example lines:
        #   SSLv3      enabled
        #   TLSv1.0    enabled
        proto_re = re.compile(r"^(SSLv2|SSLv3|TLSv1\.?0|TLSv1\.?1|TLSv1\.?2|TLSv1\.?3)\s+(enabled|disabled)", re.I)
        for line in output.splitlines():
            m = proto_re.search(line.strip())
            if not m:
                continue
            proto = m.group(1).upper().replace("TLSV1", "TLSv1")
            status = m.group(2).lower()
            protocols.append({"protocol": proto, "status": status})

        weak = [p["protocol"] for p in protocols if p.get("status") == "enabled" and p.get("protocol") in ("SSLV2", "SSLV3", "TLSv1.0", "TLSv1.1")]

        return {
            "protocols": protocols,
            "weak_protocols_enabled": weak,
        }
