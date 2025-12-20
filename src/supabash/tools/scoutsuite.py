import json
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List

from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class ScoutSuiteScanner:
    """
    Wrapper for ScoutSuite (multi-cloud security posture assessment).
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        provider: str = "aws",
        report_dir: Optional[str] = None,
        arguments: Optional[str] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute ScoutSuite for a cloud provider.

        Args:
            provider (str): aws|azure|gcp
            report_dir (str, optional): output directory for ScoutSuite reports
            arguments (str, optional): extra CLI arguments for ScoutSuite
        """
        provider = (provider or "aws").strip().lower()
        if provider not in ("aws", "azure", "gcp"):
            return {"success": False, "error": f"Unsupported ScoutSuite provider: {provider}"}

        if report_dir:
            out_dir = Path(report_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            out_dir = Path(tempfile.mkdtemp(prefix="scoutsuite-"))

        command = ["scout", provider, "--no-browser", "--report-dir", str(out_dir)]
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
                "report_dir": str(out_dir),
            }

        data, path = self._load_results(out_dir)
        findings = self._extract_findings(data)

        return {
            "success": True,
            "scan_data": {
                "provider": provider,
                "report_dir": str(out_dir),
                "results_path": str(path) if path else None,
                "findings": findings,
            },
            "command": result.command,
        }

    def _load_results(self, report_dir: Path) -> (Optional[Dict[str, Any]], Optional[Path]):
        candidates = [
            report_dir / "scoutsuite-results" / "scoutsuite-results.json",
            report_dir / "scoutsuite-results.json",
        ]
        for path in candidates:
            data = self._read_json(path)
            if data is not None:
                return data, path

        for path in report_dir.rglob("*.json"):
            data = self._read_json(path)
            if data is not None:
                return data, path
        return None, None

    def _read_json(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            if not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _extract_findings(self, data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(data, dict):
            return findings

        findings_obj = data.get("findings") or data.get("violations") or {}
        if isinstance(findings_obj, list):
            for item in findings_obj[:200]:
                if not isinstance(item, dict):
                    continue
                title = item.get("title") or item.get("description") or "ScoutSuite finding"
                severity = (item.get("severity") or item.get("level") or "INFO").upper()
                evidence = item.get("service") or item.get("resource") or ""
                findings.append(
                    {
                        "title": str(title),
                        "severity": str(severity),
                        "evidence": str(evidence),
                        "details": item,
                    }
                )
            return findings

        if isinstance(findings_obj, dict):
            for key, item in list(findings_obj.items())[:200]:
                if not isinstance(item, dict):
                    continue
                title = item.get("title") or item.get("description") or key
                severity = (item.get("severity") or item.get("level") or "INFO").upper()
                service = item.get("service") or item.get("service_name") or ""
                count = None
                items = item.get("items") or item.get("flagged_items")
                if isinstance(items, list):
                    count = len(items)
                evidence = service
                if count is not None:
                    evidence = f"{service} count={count}".strip()
                findings.append(
                    {
                        "title": str(title),
                        "severity": str(severity),
                        "evidence": str(evidence),
                        "details": item,
                    }
                )
        return findings
