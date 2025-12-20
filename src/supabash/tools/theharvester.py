import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class TheHarvesterScanner:
    """
    Wrapper for theHarvester OSINT reconnaissance tool.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        domain: str,
        sources: Optional[str] = None,
        limit: int = 500,
        start: int = 0,
        arguments: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes theHarvester scan against a domain.

        Args:
            domain (str): Target domain to harvest.
            sources (str, optional): Data sources to use (comma-separated).
                                     Default: 'all' or common sources.
                                     Examples: 'bing,google,linkedin,twitter'
            limit (int): Limit results per source (default 500).
            start (int): Start result number (for pagination).
            arguments (str, optional): Additional CLI arguments.

        Returns:
            Dict: Parsed scan results with emails, hosts, IPs, etc.
        """
        logger.info(f"Starting theHarvester on {domain}")

        # Use common sources if not specified
        if not sources:
            sources = "anubis,baidu,bing,bingapi,bufferoverun,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,sublist3r,threatcrowd,urlscan,virustotal,yahoo"

        command = [
            "theHarvester",
            "-d", domain,
            "-b", sources,
            "-l", str(limit),
            "-S", str(start),
        ]

        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=900)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        result: CommandResult = self.runner.run(command, **kwargs)

        if not result.success:
            logger.error(f"theHarvester failed: {result.stderr}")
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

        parsed = self._parse_output(result.stdout, domain)
        return {
            "success": True,
            "scan_data": parsed,
            "command": result.command,
        }

    def _parse_output(self, output: str, domain: str) -> Dict[str, Any]:
        """
        Parse theHarvester text output.
        """
        result = {
            "domain": domain,
            "emails": [],
            "hosts": [],
            "ips": [],
            "interesting_urls": [],
            "asns": [],
        }

        if not output:
            return result

        lines = output.splitlines()
        current_section = None

        # Patterns for different sections
        email_pattern = re.compile(r'[\w\.\-+]+@[\w\.\-]+\.[a-zA-Z]{2,}')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        host_pattern = re.compile(rf'[\w\.\-]+\.{re.escape(domain)}', re.IGNORECASE)

        for line in lines:
            line_stripped = line.strip()
            line_lower = line_stripped.lower()

            # Detect section headers
            if 'emails found' in line_lower or '[*] emails' in line_lower:
                current_section = 'emails'
                continue
            elif 'hosts found' in line_lower or '[*] hosts' in line_lower:
                current_section = 'hosts'
                continue
            elif 'ips found' in line_lower or '[*] ips' in line_lower:
                current_section = 'ips'
                continue
            elif 'interesting urls' in line_lower:
                current_section = 'urls'
                continue
            elif 'asns found' in line_lower or '[*] asns' in line_lower:
                current_section = 'asns'
                continue
            elif line_stripped.startswith('[*]') or line_stripped.startswith('---'):
                current_section = None
                continue

            # Skip empty lines and headers
            if not line_stripped or line_stripped.startswith('[') or line_stripped.startswith('*'):
                continue

            # Parse based on section
            if current_section == 'emails':
                emails = email_pattern.findall(line_stripped)
                for email in emails:
                    if email.lower() not in [e.lower() for e in result['emails']]:
                        result['emails'].append(email)

            elif current_section == 'hosts':
                # Format: subdomain.domain.com:ip or just subdomain.domain.com
                if ':' in line_stripped:
                    parts = line_stripped.split(':')
                    host = parts[0].strip()
                    if host and host not in result['hosts']:
                        result['hosts'].append(host)
                    if len(parts) > 1:
                        ip_matches = ip_pattern.findall(parts[1])
                        for ip in ip_matches:
                            if ip not in result['ips']:
                                result['ips'].append(ip)
                else:
                    hosts = host_pattern.findall(line_stripped)
                    for host in hosts:
                        if host not in result['hosts']:
                            result['hosts'].append(host)

            elif current_section == 'ips':
                ips = ip_pattern.findall(line_stripped)
                for ip in ips:
                    if ip not in result['ips']:
                        result['ips'].append(ip)

            elif current_section == 'urls':
                if line_stripped.startswith(('http://', 'https://')):
                    if line_stripped not in result['interesting_urls']:
                        result['interesting_urls'].append(line_stripped)

            elif current_section == 'asns':
                if line_stripped and line_stripped not in result['asns']:
                    result['asns'].append(line_stripped)

        # Also do a general sweep for emails and hosts in the whole output
        all_emails = email_pattern.findall(output)
        for email in all_emails:
            if email.lower() not in [e.lower() for e in result['emails']]:
                result['emails'].append(email)

        all_hosts = host_pattern.findall(output)
        for host in all_hosts:
            if host not in result['hosts']:
                result['hosts'].append(host)

        return result
