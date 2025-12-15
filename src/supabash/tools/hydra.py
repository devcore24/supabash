from typing import Dict, Any, Optional, List
import os
import re
import tempfile
from pathlib import Path
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class HydraRunner:
    """
    Wrapper for Hydra password brute-forcing.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def run(
        self,
        target: str,
        service: str,
        usernames: str,
        passwords: str,
        options: str = None,
        output_path: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a Hydra brute-force attempt.

        Args:
            target (str): Target host/IP (optionally host:port).
            service (str): Service module (e.g., ssh, ftp, http-get).
            usernames (str): Path to usernames file or single username.
            passwords (str): Path to passwords file or single password.
            options (str, optional): Extra Hydra CLI options.

        Returns:
            Dict: Result with success flag and raw output.
        """
        logger.info(f"Starting Hydra against {service}://{target}")

        user_flag = "-L" if ("/" in usernames or usernames.endswith((".txt", ".lst"))) else "-l"
        pass_flag = "-P" if ("/" in passwords or passwords.endswith((".txt", ".lst"))) else "-p"

        cleanup_output = False
        out_path: Optional[Path] = None
        if output_path:
            out_path = Path(output_path)
        else:
            fd, name = tempfile.mkstemp(prefix="supabash-hydra-", suffix=".out")
            os.close(fd)
            out_path = Path(name)
            cleanup_output = True

        command = [
            "hydra",
            user_flag,
            usernames,
            pass_flag,
            passwords,
            service + "://" + target,
            "-o",
            str(out_path),
        ]

        if options:
            command[1:1] = options.split()

        timeout = resolve_timeout_seconds(timeout_seconds, default=3600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        output_file_text = ""
        try:
            if out_path and out_path.exists():
                output_file_text = out_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            output_file_text = ""
        finally:
            if cleanup_output and out_path is not None:
                try:
                    out_path.unlink(missing_ok=True)  # py3.11+
                except Exception:
                    try:
                        if out_path.exists():
                            out_path.unlink()
                    except Exception:
                        pass

        combined_output = "\n".join([result.stdout or "", output_file_text]).strip()
        found_credentials = self._parse_found_credentials(combined_output)

        if not result.success:
            logger.error(f"Hydra failed: {result.stderr}")
            err = result.stderr
            if not err:
                err = result.stdout or ""
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": combined_output,
                "command": result.command,
                "service": service,
                "target": target,
                "found_credentials": found_credentials,
            }

        return {
            "success": True,
            "raw_output": combined_output,
            "command": result.command,
            "service": service,
            "target": target,
            "found_credentials": found_credentials,
        }

    def _parse_found_credentials(self, output: str) -> List[Dict[str, str]]:
        """
        Best-effort parse of Hydra success lines.

        Example formats (vary by module/version):
          [22][ssh] host: 127.0.0.1   login: root   password: toor
          host: 127.0.0.1   login: admin   password: admin
        """
        creds: List[Dict[str, str]] = []
        if not output or not isinstance(output, str):
            return creds

        patterns = [
            re.compile(
                r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>.+)",
                re.IGNORECASE,
            ),
            re.compile(
                r"host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>.+)",
                re.IGNORECASE,
            ),
        ]

        for line in output.splitlines():
            s = line.strip()
            if not s:
                continue
            for pat in patterns:
                m = pat.search(s)
                if not m:
                    continue
                d = m.groupdict()
                host = (d.get("host") or "").strip()
                login = (d.get("login") or "").strip()
                password = (d.get("password") or "").strip()
                if not host or not login:
                    continue
                creds.append(
                    {
                        "host": host,
                        "login": login,
                        "password": password,
                        "service": (d.get("service") or "").strip().lower(),
                        "port": (d.get("port") or "").strip(),
                    }
                )
                break

        return creds
