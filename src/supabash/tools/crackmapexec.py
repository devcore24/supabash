import json
import re
from typing import Dict, List, Any, Optional
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class CrackMapExecScanner:
    """
    Wrapper for CrackMapExec (CME/NetExec) - AD/Windows post-exploitation tool.

    Note: CrackMapExec has been renamed to NetExec in newer versions.
    This wrapper supports both 'crackmapexec' and 'netexec' commands.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()
        self._executable = None

    def _get_executable(self) -> str:
        """Detect available executable (netexec or crackmapexec)."""
        if self._executable:
            return self._executable

        # Try netexec first (newer), then crackmapexec
        for exe in ["netexec", "nxc", "crackmapexec", "cme"]:
            result = self.runner.run(["which", exe], timeout=5)
            if result.success and result.stdout.strip():
                self._executable = exe
                return exe

        # Default to crackmapexec
        self._executable = "crackmapexec"
        return self._executable

    def scan(
        self,
        target: str,
        protocol: str = "smb",
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        enumerate_options: Optional[List[str]] = None,
        arguments: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a CrackMapExec scan.

        Args:
            target (str): Target host, IP, or CIDR range.
            protocol (str): Protocol to use (smb, ssh, ldap, winrm, mssql, rdp).
            username (str, optional): Username for authentication.
            password (str, optional): Password for authentication.
            domain (str, optional): Domain for authentication.
            hashes (str, optional): NTLM hash (LM:NT or just NT).
            module (str, optional): Module to run (e.g., 'spider_plus', 'mimikatz').
            module_options (str, optional): Module options.
            enumerate_options (list, optional): Enumeration flags
                                                (e.g., ['--shares', '--users']).
            arguments (str, optional): Additional CLI arguments.

        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting CrackMapExec ({protocol}) on {target}")

        exe = self._get_executable()
        command = [exe, protocol, target]

        # Authentication options
        if username:
            command.extend(["-u", username])
        if password:
            command.extend(["-p", password])
        if domain:
            command.extend(["-d", domain])
        if hashes:
            command.extend(["-H", hashes])

        # Module execution
        if module:
            command.extend(["-M", module])
            if module_options:
                command.extend(["-o", module_options])

        # Enumeration options
        if enumerate_options:
            command.extend(enumerate_options)

        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"CrackMapExec failed: {result.stderr}")
            err = result.stderr
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
            }

        parsed = self._parse_output(result.stdout, protocol)
        return {
            "success": True,
            "scan_data": parsed,
            "command": result.command,
        }

    def _parse_output(self, output: str, protocol: str) -> Dict[str, Any]:
        """
        Parse CrackMapExec output.
        """
        result = {
            "protocol": protocol,
            "hosts": [],
            "credentials": [],
            "shares": [],
            "users": [],
            "groups": [],
            "sessions": [],
            "findings": [],
        }

        if not output:
            return result

        lines = output.splitlines()

        # Patterns for different output types
        # SMB host info: SMB 192.168.1.1 445 DC01 [*] Windows Server 2019 ...
        host_pattern = re.compile(
            r'^(?P<proto>\w+)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+'
            r'(?P<port>\d+)\s+(?P<hostname>\S+)\s+'
            r'\[(?P<status>[^\]]+)\]\s*(?P<info>.*)$'
        )

        # Credential found: [+] domain\user:password
        cred_pattern = re.compile(
            r'\[\+\]\s*(?:(?P<domain>[^\\]+)\\)?(?P<user>\S+):(?P<password>.+)'
        )

        # Share enumeration
        share_pattern = re.compile(
            r'(?P<share>\S+)\s+(?P<permissions>READ|WRITE|READ,WRITE|NO ACCESS)\s*(?P<remark>.*)?'
        )

        # User enumeration
        user_pattern = re.compile(
            r'(?P<domain>[^\\]+)\\(?P<user>\S+)\s+(?:badpwdcount:\s*(?P<badpwd>\d+))?\s*'
        )

        current_host = None

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Parse host info
            host_match = host_pattern.match(line_stripped)
            if host_match:
                host_info = {
                    "ip": host_match.group("ip"),
                    "port": int(host_match.group("port")),
                    "hostname": host_match.group("hostname"),
                    "status": host_match.group("status"),
                    "info": host_match.group("info").strip(),
                }
                result["hosts"].append(host_info)
                current_host = host_info
                continue

            # Parse credentials
            cred_match = cred_pattern.search(line_stripped)
            if cred_match and '[+]' in line_stripped:
                cred = {
                    "domain": cred_match.group("domain") or "",
                    "username": cred_match.group("user"),
                    "password": cred_match.group("password"),
                    "host": current_host["ip"] if current_host else None,
                }
                result["credentials"].append(cred)
                continue

            # Check for Pwn3d!
            if "Pwn3d!" in line_stripped or "(Pwn3d!)" in line_stripped:
                result["findings"].append({
                    "type": "admin_access",
                    "message": line_stripped,
                    "host": current_host["ip"] if current_host else None,
                })
                continue

            # Parse shares (when --shares is used)
            if "SHARE" in line_stripped.upper() or "READ" in line_stripped or "WRITE" in line_stripped:
                share_match = share_pattern.search(line_stripped)
                if share_match:
                    share = {
                        "name": share_match.group("share"),
                        "permissions": share_match.group("permissions"),
                        "remark": (share_match.group("remark") or "").strip(),
                        "host": current_host["ip"] if current_host else None,
                    }
                    result["shares"].append(share)

        return result

    def enum_shares(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Enumerate SMB shares.
        """
        return self.scan(
            target=target,
            protocol="smb",
            username=username,
            password=password,
            domain=domain,
            enumerate_options=["--shares"],
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def enum_users(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Enumerate domain users.
        """
        return self.scan(
            target=target,
            protocol="smb",
            username=username,
            password=password,
            domain=domain,
            enumerate_options=["--users"],
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def enum_sessions(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Enumerate active sessions.
        """
        return self.scan(
            target=target,
            protocol="smb",
            username=username,
            password=password,
            domain=domain,
            enumerate_options=["--sessions"],
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )

    def pass_the_hash(
        self,
        target: str,
        username: str,
        ntlm_hash: str,
        domain: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Attempt pass-the-hash authentication.

        Args:
            target (str): Target host or range.
            username (str): Username.
            ntlm_hash (str): NTLM hash (LM:NT or just NT hash).
            domain (str, optional): Domain.

        Returns:
            Dict: Results including success/failure of authentication.
        """
        return self.scan(
            target=target,
            protocol="smb",
            username=username,
            hashes=ntlm_hash,
            domain=domain,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )
