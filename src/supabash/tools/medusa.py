import re
from typing import Dict, List, Any, Optional
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class MedusaRunner:
    """
    Wrapper for Medusa parallel network login brute-forcer.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def run(
        self,
        target: str,
        module: str,
        usernames: str,
        passwords: str,
        port: Optional[int] = None,
        threads: int = 4,
        timeout_per_connection: int = 10,
        options: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a Medusa brute-force attempt.

        Args:
            target (str): Target host/IP.
            module (str): Service module (e.g., ssh, ftp, http, smb, mysql, postgres).
            usernames (str): Path to usernames file or single username.
            passwords (str): Path to passwords file or single password.
            port (int, optional): Target port (uses module default if not specified).
            threads (int): Number of parallel threads (default 4).
            timeout_per_connection (int): Timeout per connection in seconds.
            options (str, optional): Extra Medusa CLI options.

        Returns:
            Dict: Result with success flag, found credentials, and raw output.
        """
        logger.info(f"Starting Medusa against {module}://{target}")

        # Determine if usernames/passwords are files or single values
        user_flag = "-U" if self._is_file(usernames) else "-u"
        pass_flag = "-P" if self._is_file(passwords) else "-p"

        command = [
            "medusa",
            "-h", target,
            "-M", module,
            user_flag, usernames,
            pass_flag, passwords,
            "-t", str(threads),
            "-T", str(timeout_per_connection),
            "-O", "-",  # Output to stdout
        ]

        if port:
            command.extend(["-n", str(port)])

        if options:
            command.extend(options.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=3600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        found_credentials = self._parse_found_credentials(result.stdout)

        if not result.success:
            logger.error(f"Medusa failed: {result.stderr}")
            err = result.stderr
            if not err:
                err = result.stdout or ""
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
                "module": module,
                "target": target,
                "found_credentials": found_credentials,
            }

        return {
            "success": True,
            "raw_output": result.stdout,
            "command": result.command,
            "module": module,
            "target": target,
            "found_credentials": found_credentials,
        }

    def _is_file(self, path: str) -> bool:
        """Check if the given string looks like a file path."""
        return "/" in path or path.endswith((".txt", ".lst", ".list"))

    def _parse_found_credentials(self, output: str) -> List[Dict[str, str]]:
        """
        Parse Medusa success lines.

        Example formats:
          ACCOUNT FOUND: [ssh] Host: 192.168.1.1 User: root Password: toor [SUCCESS]
          ACCOUNT FOUND: [ftp] Host: 192.168.1.1 User: admin Password: admin123 [SUCCESS]
        """
        creds: List[Dict[str, str]] = []
        if not output or not isinstance(output, str):
            return creds

        # Pattern for successful login
        patterns = [
            # Standard format: ACCOUNT FOUND: [module] Host: x User: y Password: z [SUCCESS]
            re.compile(
                r'ACCOUNT\s+FOUND:\s*\[(?P<module>[^\]]+)\]\s+'
                r'Host:\s*(?P<host>\S+)\s+'
                r'User:\s*(?P<user>\S+)\s+'
                r'Password:\s*(?P<password>[^\[]+)'
                r'\s*\[(?P<status>[^\]]+)\]',
                re.IGNORECASE,
            ),
            # Alternative format
            re.compile(
                r'\[(?P<module>[^\]]+)\]\s+'
                r'host:\s*(?P<host>\S+)\s+'
                r'login:\s*(?P<user>\S+)\s+'
                r'password:\s*(?P<password>.+)',
                re.IGNORECASE,
            ),
        ]

        for line in output.splitlines():
            s = line.strip()
            if not s:
                continue

            # Only process lines with success indicators
            if 'FOUND' not in s.upper() and 'SUCCESS' not in s.upper():
                continue

            for pat in patterns:
                m = pat.search(s)
                if not m:
                    continue

                d = m.groupdict()
                host = (d.get("host") or "").strip()
                user = (d.get("user") or "").strip()
                password = (d.get("password") or "").strip()
                module = (d.get("module") or "").strip().lower()

                if not host or not user:
                    continue

                creds.append({
                    "host": host,
                    "login": user,
                    "password": password,
                    "module": module,
                })
                break

        return creds

    def run_ssh(
        self,
        target: str,
        usernames: str,
        passwords: str,
        port: int = 22,
        threads: int = 4,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Convenience method for SSH brute-forcing."""
        return self.run(
            target=target,
            module="ssh",
            usernames=usernames,
            passwords=passwords,
            port=port,
            threads=threads,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def run_ftp(
        self,
        target: str,
        usernames: str,
        passwords: str,
        port: int = 21,
        threads: int = 4,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Convenience method for FTP brute-forcing."""
        return self.run(
            target=target,
            module="ftp",
            usernames=usernames,
            passwords=passwords,
            port=port,
            threads=threads,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def run_smb(
        self,
        target: str,
        usernames: str,
        passwords: str,
        port: int = 445,
        threads: int = 4,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Convenience method for SMB brute-forcing."""
        return self.run(
            target=target,
            module="smbnt",
            usernames=usernames,
            passwords=passwords,
            port=port,
            threads=threads,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def run_mysql(
        self,
        target: str,
        usernames: str,
        passwords: str,
        port: int = 3306,
        threads: int = 4,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Convenience method for MySQL brute-forcing."""
        return self.run(
            target=target,
            module="mysql",
            usernames=usernames,
            passwords=passwords,
            port=port,
            threads=threads,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def run_postgres(
        self,
        target: str,
        usernames: str,
        passwords: str,
        port: int = 5432,
        threads: int = 4,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Convenience method for PostgreSQL brute-forcing."""
        return self.run(
            target=target,
            module="postgres",
            usernames=usernames,
            passwords=passwords,
            port=port,
            threads=threads,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def run_rdp(
        self,
        target: str,
        usernames: str,
        passwords: str,
        port: int = 3389,
        threads: int = 4,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Convenience method for RDP brute-forcing."""
        return self.run(
            target=target,
            module="rdp",
            usernames=usernames,
            passwords=passwords,
            port=port,
            threads=threads,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )
