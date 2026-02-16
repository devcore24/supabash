import json
import os
import tempfile
from typing import Dict, List, Any, Optional, Sequence, Union
from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)

class NucleiScanner:
    """
    Wrapper for Nuclei Vulnerability Scanner.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        target: Union[str, Sequence[str]],
        templates: str = None,
        tags: Optional[str] = None,
        severity: Optional[str] = None,
        rate_limit: int = None,
        silent: bool = False,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a Nuclei scan against the target.
        
        Args:
            target (str): IP or hostname.
            templates (str, optional): Specific templates to run (e.g., "cves", "technologies").
            rate_limit (int, optional): Requests per second limit.
            
        Returns:
            Dict: Parsed scan results.
        """
        target_list: List[str] = []
        if isinstance(target, (list, tuple, set)):
            for item in target:
                value = str(item or "").strip()
                if value and value not in target_list:
                    target_list.append(value)
        else:
            value = str(target or "").strip()
            if value:
                target_list = [value]

        if not target_list:
            return {"success": False, "error": "No valid targets provided", "command": "nuclei"}

        logger.info(
            "Starting Nuclei scan on %s",
            target_list[0] if len(target_list) == 1 else f"{len(target_list)} targets",
        )

        # Command: nuclei -u <target> -jsonl OR nuclei -l <targets_file> -jsonl
        command = ["nuclei"]
        temp_targets_file: Optional[str] = None
        if len(target_list) == 1:
            command.extend(["-u", target_list[0]])
        else:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as handle:
                handle.write("\n".join(target_list))
                handle.write("\n")
                temp_targets_file = handle.name
            command.extend(["-l", temp_targets_file])
        command.append("-jsonl")

        if silent:
            command.append("-silent")
        if templates:
            command.extend(["-t", templates])
        if tags:
            command.extend(["-tags", tags])
        if severity:
            command.extend(["-severity", severity])
        if rate_limit:
            command.extend(["-rate-limit", str(rate_limit)])

        # Nuclei can take a while depending on templates, default 30 min
        timeout = resolve_timeout_seconds(timeout_seconds, default=1800)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event
        try:
            result: CommandResult = self.runner.run(command, **kwargs)
        finally:
            if temp_targets_file:
                try:
                    os.unlink(temp_targets_file)
                except Exception:
                    pass

        if not result.success:
            logger.error(f"Nuclei scan failed: {result.stderr}")
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
            }

        parsed_data = self._parse_json(result.stdout)
        return {
            "success": True,
            "findings": parsed_data,
            "command": result.command
        }

    def _parse_json(self, json_content: str) -> List[Dict[str, Any]]:
        """
        Parses Nuclei JSON-L output.
        """
        findings = []
        if not json_content.strip():
            return findings

        for line in json_content.splitlines():
            try:
                if not line.strip():
                    continue
                finding = json.loads(line)
                
                # Simplify finding structure
                simplified = {
                    "id": finding.get("template-id"),
                    "name": finding.get("info", {}).get("name"),
                    "severity": finding.get("info", {}).get("severity"),
                    "type": finding.get("type"),
                    "host": finding.get("host"),
                    "matched_at": finding.get("matched-at"),
                    "description": finding.get("info", {}).get("description", "")
                }
                findings.append(simplified)
            except json.JSONDecodeError as e:
                # Nuclei can emit non-JSON lines depending on version/flags; ignore quietly.
                logger.debug(f"Skipping non-JSON nuclei line: {e}")
        
        return findings
