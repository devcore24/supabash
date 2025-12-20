import json
import re
from typing import Dict, List, Any, Optional
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class WPScanScanner:
    """
    Wrapper for WPScan WordPress security scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        target: str,
        api_token: Optional[str] = None,
        enumerate: Optional[str] = None,
        arguments: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a WPScan scan against a WordPress target.

        Args:
            target (str): URL to scan (must be WordPress site).
            api_token (str, optional): WPScan API token for vulnerability data.
            enumerate (str, optional): Enumeration options (e.g., 'u' for users,
                                       'p' for plugins, 't' for themes, 'vp' for
                                       vulnerable plugins, 'vt' for vulnerable themes).
            arguments (str, optional): Additional WPScan CLI arguments.

        Returns:
            Dict: Parsed scan results.
        """
        logger.info(f"Starting WPScan on {target}")

        command = ["wpscan", "--url", target, "--format", "json", "--no-banner"]

        if api_token:
            command.extend(["--api-token", api_token])

        if enumerate:
            command.extend(["--enumerate", enumerate])

        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=1200)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"WPScan failed: {result.stderr}")
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

        parsed = self._parse_json_output(result.stdout)
        return {
            "success": True,
            "scan_data": parsed,
            "command": result.command,
        }

    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """
        Parse WPScan JSON output.
        """
        try:
            data = json.loads(output)
            return {
                "target_url": data.get("target_url"),
                "effective_url": data.get("effective_url"),
                "interesting_findings": data.get("interesting_findings", []),
                "version": self._extract_version(data),
                "main_theme": data.get("main_theme"),
                "plugins": self._extract_plugins(data),
                "themes": self._extract_themes(data),
                "users": self._extract_users(data),
                "vulnerabilities": self._extract_vulnerabilities(data),
                "password_attack": data.get("password_attack"),
            }
        except json.JSONDecodeError as e:
            logger.debug(f"Failed to parse WPScan JSON: {e}")
            return {"raw_output": output, "parse_error": str(e)}

    def _extract_version(self, data: Dict) -> Optional[Dict]:
        """Extract WordPress version info."""
        version = data.get("version")
        if version:
            return {
                "number": version.get("number"),
                "status": version.get("status"),
                "interesting_entries": version.get("interesting_entries", []),
                "vulnerabilities": version.get("vulnerabilities", []),
            }
        return None

    def _extract_plugins(self, data: Dict) -> List[Dict]:
        """Extract plugin information."""
        plugins = data.get("plugins", {})
        result = []
        for name, info in plugins.items():
            result.append({
                "name": name,
                "slug": info.get("slug"),
                "version": info.get("version", {}).get("number") if info.get("version") else None,
                "location": info.get("location"),
                "vulnerabilities": info.get("vulnerabilities", []),
            })
        return result

    def _extract_themes(self, data: Dict) -> List[Dict]:
        """Extract theme information."""
        themes = data.get("themes", {})
        result = []
        for name, info in themes.items():
            result.append({
                "name": name,
                "slug": info.get("slug"),
                "version": info.get("version", {}).get("number") if info.get("version") else None,
                "location": info.get("location"),
                "vulnerabilities": info.get("vulnerabilities", []),
            })
        return result

    def _extract_users(self, data: Dict) -> List[Dict]:
        """Extract enumerated users."""
        users = data.get("users", {})
        result = []
        for username, info in users.items():
            result.append({
                "username": username,
                "id": info.get("id"),
                "slug": info.get("slug"),
            })
        return result

    def _extract_vulnerabilities(self, data: Dict) -> List[Dict]:
        """Extract all vulnerabilities from the scan."""
        vulns = []

        # Version vulnerabilities
        version = data.get("version", {})
        if version:
            for vuln in version.get("vulnerabilities", []):
                vulns.append({
                    "component": "wordpress_core",
                    "title": vuln.get("title"),
                    "type": vuln.get("vuln_type"),
                    "references": vuln.get("references", {}),
                    "fixed_in": vuln.get("fixed_in"),
                })

        # Plugin vulnerabilities
        for name, plugin in data.get("plugins", {}).items():
            for vuln in plugin.get("vulnerabilities", []):
                vulns.append({
                    "component": f"plugin:{name}",
                    "title": vuln.get("title"),
                    "type": vuln.get("vuln_type"),
                    "references": vuln.get("references", {}),
                    "fixed_in": vuln.get("fixed_in"),
                })

        # Theme vulnerabilities
        for name, theme in data.get("themes", {}).items():
            for vuln in theme.get("vulnerabilities", []):
                vulns.append({
                    "component": f"theme:{name}",
                    "title": vuln.get("title"),
                    "type": vuln.get("vuln_type"),
                    "references": vuln.get("references", {}),
                    "fixed_in": vuln.get("fixed_in"),
                })

        return vulns
