import json
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class ProwlerScanner:
    """
    Wrapper for Prowler (AWS security best-practice checks).
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        output_dir: Optional[str] = None,
        arguments: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute Prowler and parse JSON output.
        """
        if output_dir:
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            out_dir = Path(tempfile.mkdtemp(prefix="prowler-"))

        command = ["prowler", "-M", "json", "-O", str(out_dir)]
        if arguments:
            command.extend(arguments.split())

        timeout = resolve_timeout_seconds(timeout_seconds, default=3600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        result: CommandResult = self.runner.run(command, **kwargs)
        if not result.success:
            err = result.stderr
            if not err:
                err = f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": result.stdout,
                "command": result.command,
                "output_dir": str(out_dir),
            }

        records, paths = self._load_results(out_dir)
        findings = self._extract_findings(records)

        return {
            "success": True,
            "scan_data": {
                "output_dir": str(out_dir),
                "results_paths": [str(p) for p in paths],
                "findings": findings,
            },
            "command": result.command,
        }

    def _load_results(self, output_dir: Path) -> Tuple[List[Dict[str, Any]], List[Path]]:
        records: List[Dict[str, Any]] = []
        paths: List[Path] = []
        for path in sorted(output_dir.rglob("*.json")):
            data = self._read_json(path)
            if data is None:
                continue
            paths.append(path)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        records.append(item)
            elif isinstance(data, dict):
                records.append(data)
        return records, paths

    def _read_json(self, path: Path) -> Optional[Any]:
        try:
            if not path.exists():
                return None
            content = path.read_text(encoding="utf-8").strip()
            if not content:
                return None
            if content.startswith("{") or content.startswith("["):
                return json.loads(content)
            # Fall back to JSON lines
            records = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    continue
            return records
        except Exception:
            return None

    def _extract_findings(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for item in records[:2000]:
            if not isinstance(item, dict):
                continue
            status = str(item.get("Status") or item.get("status") or "").lower()
            if status in ("pass", "passed", "ok", "info") and not item.get("finding"):
                continue
            severity = (
                item.get("Severity")
                or item.get("severity")
                or item.get("SeverityLevel")
                or "MEDIUM"
            )
            title = (
                item.get("CheckID")
                or item.get("check_id")
                or item.get("CheckTitle")
                or item.get("title")
                or "Prowler finding"
            )
            resource = item.get("ResourceId") or item.get("resource_id") or ""
            account = item.get("AccountId") or item.get("account_id") or ""
            region = item.get("Region") or item.get("region") or ""
            evidence_parts = []
            if account:
                evidence_parts.append(f"account={account}")
            if region:
                evidence_parts.append(f"region={region}")
            if resource:
                evidence_parts.append(f"resource={resource}")
            if status:
                evidence_parts.append(f"status={status}")
            findings.append(
                {
                    "title": str(title),
                    "severity": str(severity).upper(),
                    "evidence": ", ".join(evidence_parts).strip(),
                    "details": item,
                }
            )
        return findings
