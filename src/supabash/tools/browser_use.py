import json
import re
import shlex
import shutil
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
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
        allow_deterministic_fallback: bool = True,
        deterministic_max_paths: int = 8,
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
            session_retry_attempted = False
            if (
                isinstance(session, str)
                and session.strip()
                and not (isinstance(command, str) and command.strip())
                and self._is_socket_timeout_error(err)
            ):
                retry_cmd = self._build_command(
                    target=target_url,
                    task=task_text,
                    max_steps=steps,
                    headless=bool(headless),
                    model=model,
                    session=None,
                    profile=profile,
                    command_override=command,
                )
                if retry_cmd:
                    if isinstance(arguments, str) and arguments.strip():
                        retry_cmd.extend(shlex.split(arguments))
                    retry_result: CommandResult = self.runner.run(retry_cmd, **kwargs)
                    session_retry_attempted = True
                    if retry_result.success:
                        result = retry_result
                        combined_output = "\n".join(
                            x for x in [retry_result.stdout, retry_result.stderr] if isinstance(x, str) and x.strip()
                        )
                        payload = self._parse_json_payload(combined_output)
                    else:
                        retry_err = (
                            retry_result.stderr
                            or retry_result.stdout
                            or f"Command failed (RC={retry_result.return_code}): {retry_result.command}"
                        )
                        err = f"{err}\nRetry without session failed: {retry_err}"
                        combined_output = "\n".join(
                            x for x in [retry_result.stdout, retry_result.stderr] if isinstance(x, str) and x.strip()
                        )
                        result = retry_result

            if not result.success:
                fallback: Optional[Dict[str, Any]] = None
                if bool(allow_deterministic_fallback) and not (isinstance(command, str) and command.strip()):
                    fallback_session = None if session_retry_attempted or self._is_socket_timeout_error(err) else session
                    fallback = self._run_deterministic_probe(
                        target_url=target_url,
                        objective_text=task_text,
                        session=fallback_session,
                        profile=profile,
                        headless=bool(headless),
                        max_paths=int(max(1, min(int(deterministic_max_paths or 8), 24))),
                        cancel_event=cancel_event,
                        timeout=timeout,
                    )
                if isinstance(fallback, dict) and bool(fallback.get("success")):
                    fallback_urls = fallback.get("urls") if isinstance(fallback.get("urls"), list) else []
                    fallback_findings = fallback.get("findings") if isinstance(fallback.get("findings"), list) else []
                    fallback_observation = (
                        fallback.get("observation") if isinstance(fallback.get("observation"), dict) else {}
                    )
                    observation = {
                        "done": False,
                        "steps": 0,
                        "data_success": False,
                        "result": "",
                        "urls_count": len(fallback_urls),
                        "findings_count": len(fallback_findings),
                        "evidence_score": int(fallback_observation.get("evidence_score") or 0),
                        "fallback_mode": "deterministic_probe_on_run_failure",
                        "fallback_steps": int(fallback_observation.get("steps") or 0),
                        "fallback_urls_count": len(fallback_urls),
                        "fallback_findings_count": len(fallback_findings),
                        "focus_urls_count": int(fallback_observation.get("focus_urls_count") or 0),
                        "focus_hits": int(fallback_observation.get("focus_hits") or 0),
                        "fallback_confidence": str(fallback_observation.get("confidence") or "low"),
                    }
                    return {
                        "success": True,
                        "target": target_url,
                        "task": task_text,
                        "urls": fallback_urls,
                        "findings": fallback_findings,
                        "observation": observation,
                        "completed": False,
                        "raw_output": combined_output,
                        "command": result.command,
                    }
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
            fallback: Optional[Dict[str, Any]] = None
            if bool(allow_deterministic_fallback) and not (isinstance(command, str) and command.strip()):
                fallback = self._run_deterministic_probe(
                    target_url=target_url,
                    objective_text=task_text,
                    session=session,
                    profile=profile,
                    headless=bool(headless),
                    max_paths=int(max(1, min(int(deterministic_max_paths or 8), 24))),
                    cancel_event=cancel_event,
                    timeout=timeout,
                )
            if isinstance(fallback, dict) and bool(fallback.get("success")):
                fallback_urls = fallback.get("urls") if isinstance(fallback.get("urls"), list) else []
                fallback_findings = fallback.get("findings") if isinstance(fallback.get("findings"), list) else []
                fallback_observation = fallback.get("observation") if isinstance(fallback.get("observation"), dict) else {}
                observation = dict(completion)
                observation.update(
                    {
                        "fallback_mode": "deterministic_probe",
                        "fallback_steps": int(fallback_observation.get("steps") or 0),
                        "fallback_urls_count": len(fallback_urls),
                        "fallback_findings_count": len(fallback_findings),
                        "evidence_score": int(
                            max(
                                int(completion.get("evidence_score") or 0),
                                int(fallback_observation.get("evidence_score") or 0),
                            )
                        ),
                        "focus_urls_count": int(fallback_observation.get("focus_urls_count") or 0),
                        "focus_hits": int(fallback_observation.get("focus_hits") or 0),
                        "fallback_confidence": str(fallback_observation.get("confidence") or "low"),
                    }
                )
                return {
                    "success": True,
                    "target": target_url,
                    "task": task_text,
                    "urls": fallback_urls,
                    "findings": fallback_findings,
                    "observation": observation,
                    "completed": False,
                    "raw_output": combined_output,
                    "command": result.command,
                }
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

    def _is_socket_timeout_error(self, error_text: Any) -> bool:
        text = str(error_text or "").strip().lower()
        if not text:
            return False
        timeout_tokens = ("timed out", "timeouterror", "socket", "recv")
        return any(token in text for token in timeout_tokens)

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
        # Prefer payload result text to avoid counting planner/task echoes embedded in JSON.
        analysis_text = payload_result if payload is not None else text
        if not analysis_text:
            analysis_text = text
        urls = self._extract_urls(analysis_text, target=target, payload=payload, result_text=payload_result)
        findings = self._extract_findings(analysis_text, target=target)
        return {"urls": urls, "findings": findings, "result_text": payload_result, "target": target}

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
        result_text: str = "",
    ) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        try:
            parsed_target = urlparse(str(target or "").strip())
        except Exception:
            parsed_target = None
        for m in re.finditer(r"https?://[^\s'\"<>`]+", text or "", flags=re.IGNORECASE):
            candidate = self._sanitize_extracted_url(str(m.group(0) or "").strip(), parsed_base=parsed_target)
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            out.append(candidate)
            if len(out) >= 200:
                break
        if isinstance(payload, dict) and len(out) < 200:
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            if isinstance(data, dict):
                current_url = self._sanitize_extracted_url(
                    str(data.get("url") or data.get("current_url") or "").strip(),
                    parsed_base=parsed_target,
                )
                if current_url and current_url not in seen:
                    seen.add(current_url)
                    out.append(current_url)
            if result_text:
                for m in re.finditer(r"https?://[^\s'\"<>`]+", result_text or "", flags=re.IGNORECASE):
                    candidate = self._sanitize_extracted_url(
                        str(m.group(0) or "").strip(),
                        parsed_base=parsed_target,
                    )
                    if not candidate or candidate in seen:
                        continue
                    seen.add(candidate)
                    out.append(candidate)
                    if len(out) >= 200:
                        break
        if not out and target:
            out.append(target)
        return out

    def _extract_findings(self, text: str, *, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen = set()
        try:
            parsed_target = urlparse(str(target or "").strip())
        except Exception:
            parsed_target = None
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

            evidence = self._sanitize_urls_in_text(line[:400], parsed_base=parsed_target)
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
        parsed_target = str(parsed.get("target") or "").strip() if isinstance(parsed, dict) else ""
        try:
            parsed_base = urlparse(parsed_target) if parsed_target else None
        except Exception:
            parsed_base = None
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
        if result_text:
            result_text = self._sanitize_urls_in_text(result_text, parsed_base=parsed_base)
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

    def _run_deterministic_probe(
        self,
        *,
        target_url: str,
        objective_text: Optional[str],
        session: Optional[str],
        profile: Optional[str],
        headless: bool,
        max_paths: int,
        cancel_event: Any,
        timeout: int,
    ) -> Dict[str, Any]:
        binary = self._resolve_cli_binary()
        if not binary:
            return {"success": False, "error": "browser-use CLI not found for deterministic probe"}

        base_cmd: List[str] = [binary, "--json"]
        if isinstance(session, str) and session.strip():
            base_cmd.extend(["--session", session.strip()])
        if isinstance(profile, str) and profile.strip():
            base_cmd.extend(["--profile", profile.strip()])
        if not headless:
            base_cmd.append("--headed")

        visited_urls: List[str] = []
        findings: List[Dict[str, Any]] = []
        seen_findings: Set[str] = set()
        probe_steps = 0
        html_cache: Dict[str, str] = {}
        meaningful_artifacts = 0
        focus_hits = 0
        focused_endpoint_artifacts = 0
        focus_urls = self._extract_task_focus_urls(
            target_url,
            objective_text or "",
            max_urls=max(2, min(int(max_paths), 24)),
        )
        focus_url_set = set(focus_urls)

        open_root = self._run_cli_json(base_cmd + ["open", target_url], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        if not open_root.get("success"):
            return {
                "success": False,
                "error": str(open_root.get("error") or "Deterministic probe could not open target"),
                "steps": probe_steps,
            }
        visited_urls.append(target_url)

        state_payload = self._run_cli_json(base_cmd + ["state"], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        title_payload = self._run_cli_json(base_cmd + ["get", "title"], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        html_payload = self._run_cli_json(base_cmd + ["get", "html"], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        root_html = str(self._extract_text_from_payload(html_payload.get("payload")) or "").strip()
        if root_html:
            html_cache[target_url] = root_html
            meaningful_artifacts += 1

        root_title = str(self._extract_text_from_payload(title_payload.get("payload")) or "").strip()
        if root_title:
            meaningful_artifacts += 1
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="INFO",
                title="Browser page title observed",
                evidence=f"{target_url} title={root_title[:180]}",
                confidence="low",
            )

        root_status, root_body, root_content_type, _root_error = self._http_probe_response(
            target_url,
            timeout_seconds=min(5, max(2, int(timeout))),
        )
        added = self._extract_response_signals(
            target_url,
            status=root_status,
            body=root_body,
            content_type=root_content_type,
            findings=findings,
            seen_findings=seen_findings,
        )
        if added > 0:
            meaningful_artifacts += int(added)
            if target_url in focus_url_set:
                focused_endpoint_artifacts += int(added)

        candidates = self._derive_probe_urls(
            target_url,
            root_html,
            max_paths=max_paths,
            prioritized_urls=focus_urls,
        )
        for candidate in candidates:
            if cancel_event is not None:
                try:
                    if cancel_event.is_set():
                        break
                except Exception:
                    pass
            open_out = self._run_cli_json(base_cmd + ["open", candidate], cancel_event=cancel_event, timeout=timeout)
            probe_steps += 1
            if not open_out.get("success"):
                continue
            if candidate in focus_url_set:
                focus_hits += 1
            if candidate not in visited_urls:
                visited_urls.append(candidate)
            title_out = self._run_cli_json(base_cmd + ["get", "title"], cancel_event=cancel_event, timeout=timeout)
            probe_steps += 1
            page_title = str(self._extract_text_from_payload(title_out.get("payload")) or "").strip()
            if page_title:
                meaningful_artifacts += 1
                if candidate in focus_url_set:
                    focused_endpoint_artifacts += 1
                    self._append_browser_finding(
                        findings,
                        seen_findings,
                        severity="MEDIUM",
                        title="Focused endpoint rendered in browser workflow",
                        evidence=(
                            f"{candidate} rendered a browser page without explicit pre-auth steps; "
                            f"title={page_title[:180]}"
                        ),
                        confidence="high",
                    )
                low_title = page_title.lower()
                if any(token in low_title for token in ("login", "sign in", "authenticate", "password")):
                    self._append_browser_finding(
                        findings,
                        seen_findings,
                        severity="MEDIUM",
                        title="Authentication surface discovered",
                        evidence=f"{candidate} title={page_title[:180]}",
                        confidence="medium",
                    )
            html_out = self._run_cli_json(base_cmd + ["get", "html"], cancel_event=cancel_event, timeout=timeout)
            probe_steps += 1
            page_html = str(self._extract_text_from_payload(html_out.get("payload")) or "").strip()
            if page_html:
                html_cache[candidate] = page_html
                meaningful_artifacts += 1
                if candidate in focus_url_set:
                    focused_endpoint_artifacts += 1
            response_status, response_body, response_content_type, _response_error = self._http_probe_response(
                candidate,
                timeout_seconds=min(5, max(2, int(timeout))),
            )
            added = self._extract_response_signals(
                candidate,
                status=response_status,
                body=response_body,
                content_type=response_content_type,
                findings=findings,
                seen_findings=seen_findings,
            )
            if added > 0:
                meaningful_artifacts += int(added)
                if candidate in focus_url_set:
                    focused_endpoint_artifacts += int(added)

        for u, html in list(html_cache.items()):
            self._extract_html_signals(u, html, findings, seen_findings)
        if not html_cache and root_html:
            self._extract_html_signals(target_url, root_html, findings, seen_findings)
        if findings:
            meaningful_artifacts += len(findings)

        evidence_score = 0
        if visited_urls and meaningful_artifacts > 0:
            evidence_score += min(len(visited_urls), 4)
        if findings:
            evidence_score += min(len(findings), 6)
        if state_payload.get("success") and meaningful_artifacts > 0:
            evidence_score += 1

        confidence = "low"
        if focused_endpoint_artifacts > 0 and findings:
            confidence = "high"
        elif focus_hits > 0 and findings:
            confidence = "high"
        elif findings:
            confidence = "medium"

        return {
            "success": bool(meaningful_artifacts > 0 and (findings or len(visited_urls) > 1)),
            "urls": visited_urls[:100],
            "findings": findings[:120],
            "observation": {
                "done": True,
                "steps": int(probe_steps),
                "evidence_score": int(evidence_score),
                "urls_count": len(visited_urls),
                "findings_count": len(findings),
                "probe_mode": "deterministic",
                "focus_urls_count": len(focus_urls),
                "focus_hits": int(focus_hits),
                "focused_endpoint_artifacts": int(focused_endpoint_artifacts),
                "confidence": confidence,
            },
        }

    def _run_cli_json(self, command: List[str], *, cancel_event: Any, timeout: int) -> Dict[str, Any]:
        result: CommandResult = self.runner.run(command, timeout=timeout, cancel_event=cancel_event)
        merged = "\n".join(
            chunk for chunk in [result.stdout, result.stderr] if isinstance(chunk, str) and chunk.strip()
        )
        payload = self._parse_json_payload(merged)
        if not result.success:
            return {
                "success": False,
                "error": str(result.stderr or result.stdout or result.error_message or "Command failed"),
                "command": result.command,
                "payload": payload,
                "raw_output": merged,
            }
        status = self._extract_cli_status(merged, payload=payload)
        if isinstance(status, dict) and status.get("ok") is False:
            return {
                "success": False,
                "error": str(status.get("error") or "browser-use reported unsuccessful command"),
                "command": result.command,
                "payload": payload,
                "raw_output": merged,
            }
        return {"success": True, "command": result.command, "payload": payload, "raw_output": merged}

    def _extract_text_from_payload(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        if isinstance(data, dict):
            for key in ("result", "text", "html", "title", "value"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        for key in ("result", "text", "html", "title", "value"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    def _extract_task_focus_urls(self, base_url: str, objective_text: str, *, max_urls: int = 12) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}".rstrip("/")
        max_urls = max(1, min(int(max_urls or 12), 40))

        def _add(url: str) -> None:
            candidate = str(url or "").strip()
            if not candidate:
                return
            normalized = self._sanitize_extracted_url(candidate, parsed_base=parsed_base)
            if not normalized:
                return
            if normalized in seen:
                return
            seen.add(normalized)
            out.append(normalized)

        for m in re.finditer(r"https?://[^\s'\"<>`]+", str(objective_text or ""), flags=re.IGNORECASE):
            raw = str(m.group(0) or "").strip().rstrip("),.;]}>")
            if raw:
                _add(raw)
                if len(out) >= max_urls:
                    return out[:max_urls]

        for m in re.finditer(r"(?<![A-Za-z0-9])(/[A-Za-z0-9._~!$&'()*+,;=:@%/\-?]+)", str(objective_text or "")):
            rel = str(m.group(1) or "").strip().rstrip("),.;]}>")
            if not rel or rel == "/":
                continue
            if rel.startswith("//"):
                # Avoid treating scheme-relative authority components as same-origin paths.
                continue
            if self._looks_like_embedded_authority_path(rel):
                # Ignore malformed artifacts like "/127.0.0.1:3003/WebGoat".
                continue
            absolute = f"{origin}{rel}"
            _add(absolute)
            if len(out) >= max_urls:
                return out[:max_urls]
        return out[:max_urls]

    def _derive_probe_urls(
        self,
        base_url: str,
        root_html: str,
        *,
        max_paths: int,
        prioritized_urls: Optional[List[str]] = None,
    ) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}".rstrip("/")
        base_path_prefix = str(parsed_base.path or "").strip().rstrip("/")
        if base_path_prefix == "/":
            base_path_prefix = ""

        for item in prioritized_urls or []:
            candidate = str(item or "").strip()
            if not candidate or candidate in seen:
                continue
            normalized = self._normalize_same_origin_url(candidate, parsed_base=parsed_base)
            if not normalized:
                continue
            seen.add(normalized)
            out.append(normalized)
            if len(out) >= max_paths:
                return out[:max_paths]

        allow_seed_paths = bool(root_html) or not base_path_prefix
        if allow_seed_paths:
            seed_paths = [
                "/login",
                "/signin",
                "/admin",
                "/manager/html",
                "/host-manager/html",
                "/api",
                "/swagger",
                "/swagger-ui",
                "/graphql",
                "/actuator",
                "/metrics",
            ]
            for rel in seed_paths:
                prefixed = f"{base_origin}{base_path_prefix}{rel}" if base_path_prefix else ""
                for candidate in [prefixed, f"{base_origin}{rel}"]:
                    if not candidate:
                        continue
                    normalized = self._normalize_same_origin_url(candidate, parsed_base=parsed_base)
                    if not normalized or normalized in seen:
                        continue
                    seen.add(normalized)
                    out.append(normalized)
                    if len(out) >= max_paths:
                        break
                if len(out) >= max_paths:
                    break
        if root_html:
            for match in re.finditer(r"""(?:href|action)\s*=\s*["']([^"']+)["']""", root_html, flags=re.IGNORECASE):
                raw = str(match.group(1) or "").strip()
                if not raw or raw.startswith(("javascript:", "mailto:", "#")):
                    continue
                absolute = urljoin(base_url, raw)
                normalized = self._normalize_same_origin_url(absolute, parsed_base=parsed_base)
                if not normalized:
                    continue
                if normalized in seen:
                    continue
                seen.add(normalized)
                out.append(normalized)
                if len(out) >= max_paths:
                    break
        return out[:max_paths]

    def _extract_html_signals(
        self,
        url: str,
        html: str,
        findings: List[Dict[str, Any]],
        seen_findings: Set[str],
    ) -> None:
        low = (html or "").lower()
        if "<form" in low:
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="MEDIUM",
                title="Form attack surface discovered",
                evidence=f"{url} contains HTML forms; validate input handling and backend API coupling.",
                confidence="medium",
            )
        if any(token in low for token in ("exception", "stack trace", "traceback", "javax.servlet", "org.apache")):
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="HIGH",
                title="Verbose error disclosure in browser workflow",
                evidence=f"{url} response includes stack-trace/exception-style content.",
                confidence="high",
            )
        if any(token in low for token in ("set-cookie", "jsessionid")) and "httponly" not in low:
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="MEDIUM",
                title="Session security header weakness",
                evidence=f"{url} indicates session cookies without explicit HttpOnly markers in observed HTML/headers.",
                confidence="medium",
            )
        if (
            "/api/v1/status/config" in str(url or "").lower()
            and any(token in low for token in ("scrape_configs", "prometheus", "remote_write", "alertmanagers"))
        ):
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="HIGH",
                title="Unauthenticated configuration exposure verified in browser workflow",
                evidence=(
                    f"{url} returned configuration-like content (e.g., scrape_configs/prometheus) "
                    "without explicit authentication workflow."
                ),
                confidence="high",
            )

    def _extract_response_signals(
        self,
        url: str,
        *,
        status: Optional[int],
        body: Optional[str],
        content_type: str,
        findings: List[Dict[str, Any]],
        seen_findings: Set[str],
    ) -> int:
        if status is None:
            return 0
        low = str(body or "").lower()
        parsed = urlparse(str(url or "").strip())
        path = str(parsed.path or "/").lower()
        query = str(parsed.query or "").lower()
        ct = str(content_type or "").lower()
        before = len(findings)

        listing_markers = ("listallmybucketsresult", "listbucketresult")
        auth_denial_markers = ("accessdenied", "invalidaccesskeyid", "signaturedoesnotmatch", "allaccessdisabled")
        object_store_probe = path == "/" or any(token in query for token in ("list-type=2", "prefix=", "delimiter=/"))

        if 200 <= int(status) < 300 and any(marker in low for marker in listing_markers):
            marker = "ListBucketResult" if "listbucketresult" in low else "ListAllMyBucketsResult"
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="HIGH",
                title="Anonymous S3-compatible bucket listing verified in browser workflow",
                evidence=(
                    f"{url} returned S3-compatible listing content without explicit authentication workflow "
                    f"(HTTP {int(status)}; marker={marker})."
                ),
                confidence="high",
            )
        elif object_store_probe and any(marker in low for marker in auth_denial_markers):
            marker = next((m for m in auth_denial_markers if m in low), "accessdenied")
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="INFO",
                title="S3-compatible listing probe rejected by auth controls",
                evidence=f"{url} returned auth-denial object-store markers (HTTP {int(status)}; marker={marker}).",
                confidence="high",
            )

        if "/api/v1/status/config" in path and 200 <= int(status) < 300:
            if any(token in low for token in ("scrape_configs", "prometheus", "remote_write", "alertmanagers")):
                self._append_browser_finding(
                    findings,
                    seen_findings,
                    severity="HIGH",
                    title="Unauthenticated configuration exposure verified in browser workflow",
                    evidence=(
                        f"{url} returned configuration-like content without explicit authentication workflow "
                        f"(HTTP {int(status)})."
                    ),
                    confidence="high",
                )

        if path.endswith("/metrics") and 200 <= int(status) < 300:
            if any(token in low for token in ("# help", "# type", "process_cpu_seconds_total", "go_gc_duration_seconds")):
                self._append_browser_finding(
                    findings,
                    seen_findings,
                    severity="MEDIUM",
                    title="Unauthenticated metrics exposure verified in browser workflow",
                    evidence=f"{url} returned metrics-style plaintext without explicit authentication workflow (HTTP {int(status)}).",
                    confidence="high",
                )

        # Low-noise hint for focused non-HTML API/object-store endpoints that returned useful content.
        if 200 <= int(status) < 300 and low and ("json" in ct or "xml" in ct or "text/plain" in ct):
            if path.endswith("/api/v1/status/config") or object_store_probe:
                self._append_browser_finding(
                    findings,
                    seen_findings,
                    severity="INFO",
                    title="Focused endpoint returned non-HTML content in browser workflow",
                    evidence=f"{url} returned {content_type or 'non-HTML content'} (HTTP {int(status)}).",
                    confidence="medium",
                )
        return len(findings) - before

    def _append_browser_finding(
        self,
        findings: List[Dict[str, Any]],
        seen_findings: Set[str],
        *,
        severity: str,
        title: str,
        evidence: str,
        confidence: str = "medium",
    ) -> None:
        sev = str(severity or "INFO").strip().upper()
        ttl = str(title or "Browser observation").strip()
        ev = str(evidence or "").strip()
        if not ev:
            return
        key = f"{sev}|{ttl}|{ev[:220]}"
        if key in seen_findings:
            return
        seen_findings.add(key)
        findings.append(
            {
                "severity": sev,
                "title": ttl,
                "evidence": ev[:400],
                "type": "browser_observation",
                "confidence": str(confidence or "medium").strip().lower()[:16] or "medium",
            }
        )

    def _http_probe_response(
        self,
        url: str,
        *,
        timeout_seconds: int = 5,
    ) -> tuple[Optional[int], Optional[str], str, Optional[str]]:
        request = Request(url, headers={"User-Agent": "supabash-browser-use-fallback/1.0"})
        try:
            with urlopen(request, timeout=max(1, int(timeout_seconds))) as response:
                status = int(response.getcode())
                content_type = str(response.headers.get("Content-Type") or "").strip()
                body = response.read(4096).decode("utf-8", errors="ignore")
                return status, body, content_type, None
        except HTTPError as e:
            status = int(getattr(e, "code", 0) or 0) or None
            content_type = str(getattr(e, "headers", {}).get("Content-Type") or "").strip()
            body = ""
            try:
                body = (e.read() or b"").decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return status, body, content_type, None
        except (URLError, TimeoutError, OSError) as e:
            return None, None, "", str(e)
        except Exception as e:
            return None, None, "", str(e)

    def _looks_like_embedded_authority_path(self, path: str) -> bool:
        text = str(path or "").strip()
        if not text.startswith("/"):
            return False
        head = text[1:].split("/", 1)[0].strip().lower()
        if not head:
            return False
        if head.startswith("http:") or head.startswith("https:"):
            return True
        if ":" not in head:
            return False
        host_part, maybe_port = head.rsplit(":", 1)
        if not maybe_port.isdigit():
            return False
        if "." not in host_part and host_part not in {"localhost"} and ":" not in host_part:
            return False
        if not re.fullmatch(r"[a-z0-9.\-\[\]:]+", host_part):
            return False
        return True

    def _strip_trailing_url_artifacts(self, value: str) -> str:
        text = str(value or "").strip()
        while text:
            last = text[-1]
            if last in ",;>.":
                text = text[:-1].rstrip()
                continue
            if last == ")" and text.count("(") < text.count(")"):
                text = text[:-1].rstrip()
                continue
            if last == "]" and text.count("[") < text.count("]"):
                text = text[:-1].rstrip()
                continue
            if last == "}" and text.count("{") < text.count("}"):
                text = text[:-1].rstrip()
                continue
            break
        return text

    def _sanitize_extracted_url(self, candidate: str, *, parsed_base=None) -> Optional[str]:
        text = self._strip_trailing_url_artifacts(candidate)
        if not text.startswith(("http://", "https://")):
            return None
        try:
            parsed = urlparse(text)
        except Exception:
            return None
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        if parsed_base is not None and getattr(parsed_base, "netloc", None) == parsed.netloc:
            normalized = self._normalize_same_origin_url(text, parsed_base=parsed_base)
            if normalized:
                return normalized
            return None
        return text

    def _sanitize_urls_in_text(self, value: str, *, parsed_base=None) -> str:
        text = str(value or "")
        if not text:
            return ""

        def repl(match: re.Match) -> str:
            raw = str(match.group(0) or "")
            sanitized = self._sanitize_extracted_url(raw, parsed_base=parsed_base)
            return sanitized if sanitized else self._strip_trailing_url_artifacts(raw)

        return re.sub(r"https?://[^\s'\"<>`]+", repl, text, flags=re.IGNORECASE)

    def _normalize_same_origin_url(self, candidate: str, *, parsed_base) -> Optional[str]:
        text = self._strip_trailing_url_artifacts(candidate)
        if not text:
            return None
        try:
            parsed = urlparse(text)
        except Exception:
            return None
        if parsed.scheme not in ("http", "https"):
            return None
        if parsed.netloc != parsed_base.netloc:
            return None
        path = re.sub(r"/{2,}", "/", str(parsed.path or "/"))
        if self._looks_like_embedded_authority_path(path):
            return None
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized = f"{normalized}?{parsed.query}"
        return normalized
