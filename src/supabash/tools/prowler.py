import json
import shlex
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

    OCSF_SUFFIX = ".ocsf.json"
    MAX_NORMALIZED_FINDINGS = 2000

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
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            # A caller may intentionally reuse its report directory. Isolate each
            # invocation so a prior run's JSON cannot be mistaken for current
            # evidence.
            out_dir = Path(
                tempfile.mkdtemp(prefix="prowler-run-", dir=str(output_root))
            )
        else:
            out_dir = Path(tempfile.mkdtemp(prefix="prowler-"))

        # Prowler 5 requires a provider subcommand.  OCSF is its portable,
        # machine-readable JSON format; ``-O`` is an AWS organizations role,
        # not an output directory.
        command = ["prowler", "aws"]
        if arguments:
            command.extend(shlex.split(arguments))
        command.extend(
            [
                "--output-formats",
                "json-ocsf",
                "--output-directory",
                str(out_dir),
                "--ignore-exit-code-3",
                "--no-banner",
                "--no-color",
            ]
        )

        timeout = resolve_timeout_seconds(timeout_seconds, default=3600)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        result: CommandResult = self.runner.run(command, **kwargs)
        records, paths, parse_diagnostics = self._load_results_with_diagnostics(
            out_dir
        )
        scan_data = {
            "output_dir": str(out_dir),
            "results_paths": [str(p) for p in paths],
            "parse_diagnostics": parse_diagnostics,
            "raw_record_count": len(records),
            "coverage_complete": bool(result.success) and all(
                item.get("status") == "parsed" for item in parse_diagnostics
            ),
        }

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
                "scan_data": scan_data,
            }

        if not paths:
            return {
                "success": False,
                "error": (
                    "Prowler exited successfully but produced no parseable JSON "
                    "result artifact; scan coverage cannot be verified."
                ),
                "raw_output": result.stdout,
                "raw_error": result.stderr,
                "command": result.command,
                "output_dir": str(out_dir),
                "scan_data": scan_data,
            }

        total_findings = sum(1 for item in records if self._record_is_finding(item))
        findings = self._extract_findings(
            records,
            limit=self.MAX_NORMALIZED_FINDINGS,
        )
        scan_data["findings"] = findings
        scan_data["finding_count"] = total_findings
        scan_data["normalized_finding_count"] = len(findings)
        scan_data["findings_truncated"] = total_findings > len(findings)
        if scan_data["findings_truncated"]:
            scan_data["coverage_complete"] = False

        return {
            "success": True,
            "scan_data": scan_data,
            "command": result.command,
        }

    def _load_results(self, output_dir: Path) -> Tuple[List[Dict[str, Any]], List[Path]]:
        records, paths, _ = self._load_results_with_diagnostics(output_dir)
        return records, paths

    def _load_results_with_diagnostics(
        self, output_dir: Path
    ) -> Tuple[List[Dict[str, Any]], List[Path], List[Dict[str, Any]]]:
        records: List[Dict[str, Any]] = []
        paths: List[Path] = []
        diagnostics: List[Dict[str, Any]] = []
        candidates = sorted(output_dir.rglob(f"*{self.OCSF_SUFFIX}"))
        if not candidates:
            diagnostics.append(
                {
                    "path": str(output_dir),
                    "status": "missing",
                    "message": "No JSON result artifacts were found.",
                }
            )
            return records, paths, diagnostics

        seen_records = set()
        for path in candidates:
            data, diagnostic = self._read_json_with_diagnostics(path)
            diagnostics.append(diagnostic)
            if data is None:
                continue
            normalized = self._records_from_payload(data)
            valid_records = [item for item in normalized if self._is_ocsf_record(item)]
            rejected_count = len(normalized) - len(valid_records)
            diagnostic["record_count"] = len(valid_records)
            diagnostic["rejected_record_count"] = rejected_count
            if rejected_count:
                diagnostic["status"] = "parsed_with_warnings"
                diagnostic["message"] = (
                    f"Rejected {rejected_count} record(s) that did not match the "
                    "Prowler OCSF finding contract."
                )
            # Prowler writes a top-level array; an empty array is a valid clean
            # result. An arbitrary object such as {} must not become evidence.
            if not valid_records and normalized:
                continue
            if not valid_records and not isinstance(data, list):
                diagnostic["status"] = "ignored"
                diagnostic["message"] = "OCSF artifact was not a top-level finding array."
                continue

            duplicate_count = 0
            deduplicated = []
            for item in valid_records:
                fingerprint = json.dumps(item, sort_keys=True, separators=(",", ":"))
                if fingerprint in seen_records:
                    duplicate_count += 1
                    continue
                seen_records.add(fingerprint)
                deduplicated.append(item)
            diagnostic["duplicate_record_count"] = duplicate_count
            paths.append(path)
            records.extend(deduplicated)
        return records, paths, diagnostics

    def _read_json(self, path: Path) -> Optional[Any]:
        data, _ = self._read_json_with_diagnostics(path)
        return data

    def _read_json_with_diagnostics(
        self, path: Path
    ) -> Tuple[Optional[Any], Dict[str, Any]]:
        diagnostic: Dict[str, Any] = {
            "path": str(path),
            "status": "ignored",
        }
        try:
            if not path.exists():
                diagnostic["message"] = "Artifact disappeared before it could be read."
                return None, diagnostic
            content = path.read_text(encoding="utf-8").strip()
            if not content:
                diagnostic["message"] = "Artifact was empty."
                return None, diagnostic
            try:
                data = json.loads(content)
                if not isinstance(data, (dict, list)):
                    diagnostic["message"] = (
                        "Top-level JSON value was not an object or array."
                    )
                    return None, diagnostic
                diagnostic.update({"status": "parsed", "format": "json"})
                return data, diagnostic
            except json.JSONDecodeError as exc:
                whole_file_error = {
                    "line": exc.lineno,
                    "column": exc.colno,
                    "message": exc.msg,
                }
                pass

            # Some Prowler integrations emit JSON Lines. A JSONL document starts
            # with ``{`` too, so this fallback must run after whole-file parsing.
            records = []
            errors: List[Dict[str, Any]] = []
            ignored_line_count = 0
            for line_number, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if not isinstance(item, (dict, list)):
                        raise ValueError("JSONL value was not an object or array")
                    records.append(item)
                except (json.JSONDecodeError, ValueError) as exc:
                    ignored_line_count += 1
                    if len(errors) < 20:
                        errors.append(
                            {
                                "line": line_number,
                                "message": str(exc),
                            }
                        )
                    continue
            if not records:
                diagnostic.update(
                    {
                        "message": "Artifact was neither valid JSON nor valid JSONL.",
                        "whole_file_error": whole_file_error,
                        "ignored_line_count": ignored_line_count,
                        "errors": errors,
                    }
                )
                return None, diagnostic

            status = "parsed_with_warnings" if ignored_line_count else "parsed"
            diagnostic.update(
                {
                    "status": status,
                    "format": "jsonl",
                    "ignored_line_count": ignored_line_count,
                    "errors": errors,
                }
            )
            return records, diagnostic
        except Exception as exc:
            diagnostic["message"] = f"{type(exc).__name__}: {exc}"
            return None, diagnostic

    def _records_from_payload(self, payload: Any) -> List[Dict[str, Any]]:
        """Normalize arrays, JSONL payloads, and common result envelopes."""
        if isinstance(payload, list):
            records: List[Dict[str, Any]] = []
            for item in payload:
                records.extend(self._records_from_payload(item))
            return records
        if not isinstance(payload, dict):
            return []

        envelope_keys = (
            "findings",
            "Findings",
            "results",
            "Results",
            "items",
            "Items",
            "records",
            "Records",
        )
        for key in envelope_keys:
            nested = payload.get(key)
            if isinstance(nested, (dict, list)):
                return self._records_from_payload(nested)
        return [payload]

    def _is_ocsf_record(self, item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        finding_info = item.get("finding_info")
        metadata = item.get("metadata")
        status_code = str(item.get("status_code") or "").strip().upper()
        return bool(
            isinstance(finding_info, dict)
            and isinstance(metadata, dict)
            and str(metadata.get("event_code") or "").strip()
            and status_code in {"PASS", "FAIL", "MANUAL", "MUTED"}
        )

    @staticmethod
    def _mapping(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _first_value(*values: Any) -> Any:
        for value in values:
            if value is not None and str(value).strip():
                return value
        return None

    def _severity(self, item: Dict[str, Any]) -> str:
        severity_obj = item.get("Severity")
        severity_mapping = self._mapping(severity_obj)
        value = self._first_value(
            item.get("severity"),
            severity_mapping.get("Label"),
            severity_mapping.get("label"),
            severity_mapping.get("Original"),
            severity_obj if not isinstance(severity_obj, dict) else None,
            item.get("SeverityLevel"),
        )
        if value is None:
            severity_ids = {
                0: "INFO",
                1: "INFO",
                2: "LOW",
                3: "MEDIUM",
                4: "HIGH",
                5: "CRITICAL",
                6: "CRITICAL",
                99: "INFO",
            }
            try:
                value = severity_ids.get(int(item.get("severity_id")), "MEDIUM")
            except (TypeError, ValueError):
                value = "MEDIUM"

        normalized = str(value).strip().upper().replace(" ", "_")
        aliases = {
            "INFORMATION": "INFO",
            "INFORMATIONAL": "INFO",
            "UNKNOWN": "INFO",
            "OTHER": "INFO",
            "FATAL": "CRITICAL",
        }
        return aliases.get(normalized, normalized or "MEDIUM")

    def _record_is_finding(self, item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        compliance = self._mapping(item.get("Compliance") or item.get("compliance"))
        status_value = self._first_value(
            item.get("Status"),
            item.get("status_code"),
            compliance.get("Status"),
            compliance.get("status"),
            item.get("status"),
        )
        status = str(status_value or "").strip().lower()
        return not (status in ("pass", "passed", "ok", "info") and not item.get("finding"))

    def _extract_findings(
        self,
        records: List[Dict[str, Any]],
        *,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        finding_limit = None if limit is None else max(0, int(limit))
        for item in records:
            if not isinstance(item, dict):
                continue

            finding_info = self._mapping(item.get("finding_info"))
            metadata = self._mapping(item.get("metadata"))
            compliance = self._mapping(item.get("Compliance") or item.get("compliance"))
            cloud = self._mapping(item.get("cloud"))
            cloud_account = self._mapping(cloud.get("account"))

            status_value = self._first_value(
                item.get("Status"),
                item.get("status_code"),
                compliance.get("Status"),
                compliance.get("status"),
                item.get("status"),
            )
            status = str(status_value or "").strip().lower()
            if not self._record_is_finding(item):
                continue
            if finding_limit is not None and len(findings) >= finding_limit:
                break

            check_id = self._first_value(
                item.get("CheckID"),
                item.get("check_id"),
                metadata.get("event_code"),
                item.get("GeneratorId"),
            )
            title = self._first_value(
                item.get("CheckTitle"),
                item.get("Title"),
                item.get("title"),
                finding_info.get("title"),
                check_id,
                "Prowler finding",
            )

            resources_obj = item.get("Resources") or item.get("resources") or []
            resources = resources_obj if isinstance(resources_obj, list) else []
            first_resource = self._mapping(resources[0]) if resources else {}
            resource = self._first_value(
                item.get("ResourceId"),
                item.get("resource_id"),
                first_resource.get("Id"),
                first_resource.get("id"),
                first_resource.get("uid"),
                first_resource.get("name"),
            )
            account = self._first_value(
                item.get("AccountId"),
                item.get("account_id"),
                item.get("AwsAccountId"),
                cloud_account.get("uid"),
            )
            region = self._first_value(
                item.get("Region"),
                item.get("region"),
                first_resource.get("Region"),
                first_resource.get("region"),
                cloud.get("region"),
            )
            evidence_parts = []
            if account:
                evidence_parts.append(f"account={account}")
            if region:
                evidence_parts.append(f"region={region}")
            if resource:
                evidence_parts.append(f"resource={resource}")
            if status:
                evidence_parts.append(f"status={status}")

            description = self._first_value(
                item.get("Description"),
                item.get("description"),
                item.get("status_detail"),
                item.get("message"),
                finding_info.get("desc"),
            )
            remediation_obj = self._mapping(
                item.get("Remediation") or item.get("remediation")
            )
            recommendation = self._mapping(remediation_obj.get("Recommendation"))
            remediation = self._first_value(
                remediation_obj.get("desc"),
                recommendation.get("Text"),
                recommendation.get("text"),
            )

            finding: Dict[str, Any] = {
                "title": str(title),
                "severity": self._severity(item),
                "evidence": ", ".join(evidence_parts).strip(),
                "details": item,
            }
            if check_id:
                finding["check_id"] = str(check_id)
            if description:
                finding["description"] = str(description)
            if remediation:
                finding["remediation"] = str(remediation)
            if resource:
                finding["resource"] = str(resource)
            findings.append(finding)
        return findings
