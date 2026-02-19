import json
import re
import shlex
import shutil
from urllib.parse import urljoin, urlparse
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
        findings = self._extract_findings(analysis_text)
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
        result_text: str = "",
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
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            if isinstance(data, dict):
                current_url = str(data.get("url") or data.get("current_url") or "").strip()
                if current_url.startswith(("http://", "https://")) and current_url not in seen:
                    seen.add(current_url)
                    out.append(current_url)
            if result_text:
                for m in re.finditer(r"https?://[^\s'\"<>`]+", result_text or "", flags=re.IGNORECASE):
                    candidate = str(m.group(0) or "").strip().rstrip(".,;")
                    if not candidate or candidate in seen:
                        continue
                    seen.add(candidate)
                    out.append(candidate)
                    if len(out) >= 200:
                        break
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

    def _run_deterministic_probe(
        self,
        *,
        target_url: str,
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
            )

        candidates = self._derive_probe_urls(target_url, root_html, max_paths=max_paths)
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
            if candidate not in visited_urls:
                visited_urls.append(candidate)
            title_out = self._run_cli_json(base_cmd + ["get", "title"], cancel_event=cancel_event, timeout=timeout)
            probe_steps += 1
            page_title = str(self._extract_text_from_payload(title_out.get("payload")) or "").strip()
            if page_title:
                meaningful_artifacts += 1
                low_title = page_title.lower()
                if any(token in low_title for token in ("login", "sign in", "authenticate", "password")):
                    self._append_browser_finding(
                        findings,
                        seen_findings,
                        severity="MEDIUM",
                        title="Authentication surface discovered",
                        evidence=f"{candidate} title={page_title[:180]}",
                    )

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

    def _derive_probe_urls(self, base_url: str, root_html: str, *, max_paths: int) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}".rstrip("/")
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
            candidate = f"{base_origin}{rel}"
            if candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
        if root_html:
            for match in re.finditer(r"""(?:href|action)\s*=\s*["']([^"']+)["']""", root_html, flags=re.IGNORECASE):
                raw = str(match.group(1) or "").strip()
                if not raw or raw.startswith(("javascript:", "mailto:", "#")):
                    continue
                absolute = urljoin(base_url, raw)
                parsed = urlparse(absolute)
                if parsed.scheme not in ("http", "https"):
                    continue
                if parsed.netloc != parsed_base.netloc:
                    continue
                normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                if parsed.query:
                    normalized = f"{normalized}?{parsed.query}"
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
            )
        if any(token in low for token in ("exception", "stack trace", "traceback", "javax.servlet", "org.apache")):
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="HIGH",
                title="Verbose error disclosure in browser workflow",
                evidence=f"{url} response includes stack-trace/exception-style content.",
            )
        if any(token in low for token in ("set-cookie", "jsessionid")) and "httponly" not in low:
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="MEDIUM",
                title="Session security header weakness",
                evidence=f"{url} indicates session cookies without explicit HttpOnly markers in observed HTML/headers.",
            )

    def _append_browser_finding(
        self,
        findings: List[Dict[str, Any]],
        seen_findings: Set[str],
        *,
        severity: str,
        title: str,
        evidence: str,
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
            }
        )
