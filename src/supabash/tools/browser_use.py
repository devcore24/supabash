import json
import re
import shlex
import shutil
from typing import Any, Dict, List, Optional, Set

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class BrowserUseScanner:
    """
    Best-effort wrapper for browser-use CLI automation.

    Notes:
    - This wrapper is intentionally defensive because browser-use deployments vary.
    - If the browser-use CLI is unavailable, calls fail fast with a clear error.
    - Results are parsed heuristically from stdout/stderr into URLs + finding signals.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def is_available(self, command_override: Optional[str] = None) -> bool:
        if isinstance(command_override, str) and command_override.strip():
            return True
        return bool(self._resolve_cli_binary())

    def scan(
        self,
        target: str,
        *,
        task: Optional[str] = None,
        max_steps: int = 25,
        headless: bool = True,
        model: Optional[str] = None,
        session: Optional[str] = None,
        profile: Optional[str] = None,
        arguments: Optional[str] = None,
        command: Optional[str] = None,
        require_done: bool = True,
        min_steps_success: int = 1,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        target_url = str(target or "").strip()
        if not target_url:
            return {"success": False, "error": "No browser target provided", "command": ""}
        if not target_url.startswith(("http://", "https://")):
            return {"success": False, "error": "Browser target must include http:// or https://", "command": ""}

        steps = max(1, min(int(max_steps or 25), 100))
        task_text = str(task or "").strip()
        if not task_text:
            task_text = (
                f"Open {target_url} and inspect for security-relevant issues, exposed endpoints, "
                "authentication weaknesses, and sensitive data leakage."
            )

        command_list = self._build_command(
            target=target_url,
            task=task_text,
            max_steps=steps,
            headless=bool(headless),
            model=model,
            session=session,
            profile=profile,
            command_override=command,
        )
        if not command_list:
            return {
                "success": False,
                "error": "browser-use CLI not found (install browser-use or configure tools.browser_use.command).",
                "command": "",
            }
        if isinstance(arguments, str) and arguments.strip():
            command_list.extend(shlex.split(arguments))

        timeout = resolve_timeout_seconds(timeout_seconds, default=900)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        logger.info(f"Starting browser_use scan on {target_url}")
        result: CommandResult = self.runner.run(command_list, **kwargs)
        combined_output = "\n".join(x for x in [result.stdout, result.stderr] if isinstance(x, str) and x.strip())
        payload = self._parse_json_payload(combined_output)

        if not result.success:
            err = result.stderr or result.stdout or f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": combined_output,
                "command": result.command,
            }

        status = self._extract_cli_status(combined_output, payload=payload)
        if isinstance(status, dict) and status.get("ok") is False:
            return {
                "success": False,
                "error": str(status.get("error") or "browser-use reported unsuccessful run"),
                "canceled": False,
                "raw_output": combined_output,
                "command": result.command,
            }

        parsed = self._parse_output(combined_output, target_url, payload=payload)
        completion = self._extract_completion(payload, parsed)
        try:
            min_steps = int(min_steps_success)
        except Exception:
            min_steps = 1
        min_steps = max(0, min(min_steps, 100))
        completion_error: Optional[str] = None
        if bool(require_done) and completion.get("done") is False:
            completion_error = (
                "browser-use run did not complete (done=false); no actionable browser evidence collected"
            )
        elif completion.get("steps") is not None and int(completion.get("steps") or 0) < min_steps:
            evidence_score = int(completion.get("evidence_score") or 0)
            if evidence_score <= 0:
                completion_error = (
                    f"browser-use run below minimum completed steps "
                    f"(steps={int(completion.get('steps') or 0)}, required={min_steps})"
                )
        elif completion.get("done") is None and completion.get("steps") is None:
            evidence_score = int(completion.get("evidence_score") or 0)
            if evidence_score <= 0:
                completion_error = "browser-use returned no completion telemetry and no security-relevant evidence"

        if completion_error:
            return {
                "success": False,
                "error": completion_error,
                "canceled": False,
                "target": target_url,
                "task": task_text,
                "observation": completion,
                "raw_output": combined_output,
                "command": result.command,
            }

        return {
            "success": True,
            "target": target_url,
            "task": task_text,
            "urls": parsed.get("urls", []),
            "findings": parsed.get("findings", []),
            "observation": completion,
            "completed": bool(completion.get("done")) if completion.get("done") is not None else True,
            "raw_output": combined_output,
            "command": result.command,
        }

    def _resolve_cli_binary(self) -> Optional[str]:
        for candidate in ("browser-use", "browser_use"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    def _build_command(
        self,
        *,
        target: str,
        task: str,
        max_steps: int,
        headless: bool,
        model: Optional[str],
        session: Optional[str],
        profile: Optional[str],
        command_override: Optional[str],
    ) -> Optional[List[str]]:
        if isinstance(command_override, str) and command_override.strip():
            fmt_values = {
                "target": target,
                "task": task,
                "max_steps": int(max_steps),
                "headless": "true" if headless else "false",
                "model": str(model or "").strip(),
                "session": str(session or "").strip(),
                "profile": str(profile or "").strip(),
            }
            templ = command_override.strip()
            try:
                templ = templ.format(**fmt_values)
            except Exception:
                pass
            parsed = shlex.split(templ)
            return parsed if parsed else None

        binary = self._resolve_cli_binary()
        if not binary:
            return None

        command = [binary, "--json"]
        if isinstance(session, str) and session.strip():
            command.extend(["--session", session.strip()])
        if isinstance(profile, str) and profile.strip():
            command.extend(["--profile", profile.strip()])
        # browser-use CLI exposes --headed (no --headless flag).
        if not headless:
            command.append("--headed")
        # Keep model handling to command_override; native CLI doesn't expose --model.
        _ = model
        command.extend(["run", task, "--max-steps", str(int(max_steps))])
        return command

    def _parse_output(self, output: str, target: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        text = str(output or "")
        payload_result = self._payload_result_text(payload)
        merged_text = text
        if payload_result:
            merged_text = f"{text}\n{payload_result}" if text else payload_result
        urls = self._extract_urls(merged_text, target=target, payload=payload)
        findings = self._extract_findings(merged_text)
        return {"urls": urls, "findings": findings, "result_text": payload_result}

    def _extract_cli_status(self, output: str, payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        text = str(output or "").strip()
        if payload is None:
            payload = self._parse_json_payload(text)
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict) and "success" in data and not bool(data.get("success")):
                return {"ok": False, "error": str(data.get("error") or "").strip()}
            if "success" in payload and not bool(payload.get("success")):
                return {"ok": False, "error": str(payload.get("error") or "").strip()}
            return {"ok": True}

        if re.search(r"\bsuccess\s*:\s*false\b", text, flags=re.IGNORECASE):
            m = re.search(r"\berror\s*:\s*(.+)$", text, flags=re.IGNORECASE | re.DOTALL)
            err = m.group(1).strip() if m else "browser-use reported unsuccessful run"
            return {"ok": False, "error": err}
        return None

    def _parse_json_payload(self, text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        for line in reversed(text.splitlines()):
            line = str(line or "").strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
        return None

    def _extract_urls(
        self,
        text: str,
        *,
        target: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        for m in re.finditer(r"https?://[^\s'\"<>`]+", text or "", flags=re.IGNORECASE):
            candidate = str(m.group(0) or "").strip().rstrip(".,;")
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            out.append(candidate)
            if len(out) >= 200:
                break
        if isinstance(payload, dict) and len(out) < 200:
            self._collect_urls_from_obj(payload, out, seen)
        if not out and target:
            out.append(target)
        return out

    def _extract_findings(self, text: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen = set()
        signal_tokens = (
            "vuln",
            "vulnerability",
            "misconfig",
            "exposed",
            "unauth",
            "sql injection",
            "xss",
            "csrf",
            "idor",
            "rce",
            "token",
            "secret",
            "password",
            "auth bypass",
            "directory listing",
            "open redirect",
            "insecure",
        )

        for raw in (text or "").splitlines():
            line = str(raw or "").strip()
            if not line:
                continue
            low = line.lower()
            if not any(tok in low for tok in signal_tokens):
                continue

            sev = "MEDIUM"
            if any(k in low for k in ("critical", "rce", "auth bypass", "sql injection")):
                sev = "HIGH"
            if any(k in low for k in ("info", "observed", "note:")):
                sev = "INFO"

            title = "Browser-driven security signal"
            if "sql injection" in low:
                title = "Potential SQL Injection signal"
            elif "xss" in low:
                title = "Potential XSS signal"
            elif "auth" in low and "bypass" in low:
                title = "Potential authentication bypass signal"
            elif "token" in low or "secret" in low or "password" in low:
                title = "Potential secret exposure signal"
            elif "misconfig" in low or "insecure" in low:
                title = "Potential security misconfiguration signal"

            evidence = line[:400]
            dedup_key = f"{sev}|{title}|{evidence}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(
                {
                    "severity": sev,
                    "title": title,
                    "evidence": evidence,
                    "type": "browser_observation",
                }
            )
            if len(findings) >= 120:
                break
        return findings

    def _collect_urls_from_obj(self, value: Any, out: List[str], seen: Set[str]) -> None:
        if len(out) >= 200:
            return
        if isinstance(value, str):
            for m in re.finditer(r"https?://[^\s'\"<>`]+", value, flags=re.IGNORECASE):
                candidate = str(m.group(0) or "").strip().rstrip(".,;")
                if not candidate or candidate in seen:
                    continue
                seen.add(candidate)
                out.append(candidate)
                if len(out) >= 200:
                    return
            return
        if isinstance(value, dict):
            for v in value.values():
                self._collect_urls_from_obj(v, out, seen)
                if len(out) >= 200:
                    return
            return
        if isinstance(value, list):
            for item in value:
                self._collect_urls_from_obj(item, out, seen)
                if len(out) >= 200:
                    return

    def _payload_result_text(self, payload: Optional[Dict[str, Any]]) -> str:
        if not isinstance(payload, dict):
            return ""
        data = payload.get("data")
        if not isinstance(data, dict):
            return ""
        result = data.get("result")
        if result is None:
            return ""
        if isinstance(result, str):
            return result.strip()
        try:
            return json.dumps(result, ensure_ascii=False)
        except Exception:
            return str(result)

    def _extract_completion(self, payload: Optional[Dict[str, Any]], parsed: Dict[str, Any]) -> Dict[str, Any]:
        done: Optional[bool] = None
        steps: Optional[int] = None
        data_success: Optional[bool] = None
        run_id: Optional[str] = None
        result_text = str(parsed.get("result_text") or "").strip() if isinstance(parsed, dict) else ""
        if isinstance(payload, dict):
            run_id_raw = payload.get("id")
            if isinstance(run_id_raw, str) and run_id_raw.strip():
                run_id = run_id_raw.strip()
            data = payload.get("data")
            if isinstance(data, dict):
                done_raw = data.get("done")
                if isinstance(done_raw, bool):
                    done = done_raw
                if "success" in data:
                    data_success = bool(data.get("success"))
                steps_raw = data.get("steps")
                if steps_raw is not None:
                    try:
                        steps = int(steps_raw)
                    except Exception:
                        steps = None
                if not result_text:
                    result_text = self._payload_result_text(payload)
        urls_count = len(parsed.get("urls") or []) if isinstance(parsed, dict) else 0
        findings_count = len(parsed.get("findings") or []) if isinstance(parsed, dict) else 0
        evidence_score = 0
        if findings_count > 0:
            evidence_score += min(findings_count, 5)
        if urls_count > 1:
            evidence_score += 1
        if result_text:
            evidence_score += 1
        return {
            "id": run_id,
            "done": done,
            "steps": steps,
            "data_success": data_success,
            "result": result_text[:2000] if result_text else "",
            "urls_count": urls_count,
            "findings_count": findings_count,
            "evidence_score": int(evidence_score),
        }
