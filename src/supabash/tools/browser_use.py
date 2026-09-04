import json
import os
import re
import shlex
import shutil
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError
from typing import Any, Dict, List, Optional, Sequence, Set

from supabash.logger import setup_logger
from supabash.runner import CommandResult, CommandRunner
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)

_BROWSER_USE_FINDING_SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


class _NoRedirectHandler(HTTPRedirectHandler):
    """Return redirect responses to the caller instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_BROWSER_USE_LIBRARY_RUNNER = r"""
import asyncio
import json
import logging
import sys

task = sys.argv[1]
max_steps = int(sys.argv[2])
headless = sys.argv[3] == "1"
model = sys.argv[4] or None
profile = sys.argv[5] or None
allowed_origins = json.loads(sys.argv[6]) if len(sys.argv) > 6 else []

for name in ("browser_use", "Agent", "BrowserSession", "service", "tools"):
    logging.getLogger(name).setLevel(logging.ERROR)
logging.getLogger().setLevel(logging.ERROR)


async def main():
    browser = None
    try:
        from browser_use import Agent, Browser, ChatBrowserUse

        browser_kwargs = {"headless": headless}
        if profile:
            browser_kwargs["profile_directory"] = profile
        if allowed_origins:
            browser_kwargs["allowed_domains"] = allowed_origins
            browser_kwargs["cross_origin_iframes"] = False
        browser = Browser(**browser_kwargs)
        llm = ChatBrowserUse(model=model) if model else ChatBrowserUse()
        agent = Agent(task=task, llm=llm, browser=browser)
        result = await agent.run(max_steps=max_steps)

        urls = []
        if hasattr(result, "urls"):
            try:
                maybe_urls = result.urls()
                if isinstance(maybe_urls, (list, tuple)):
                    urls = [str(x) for x in maybe_urls if str(x or "").strip()]
            except Exception:
                urls = []

        final_result = None
        if hasattr(result, "final_result"):
            try:
                final_result = result.final_result()
            except Exception:
                final_result = None

        done = None
        if hasattr(result, "is_done"):
            try:
                done = bool(result.is_done())
            except Exception:
                done = None

        steps = None
        try:
            steps = len(result)
        except Exception:
            steps = None

        current_url = urls[-1] if urls else None
        print(
            json.dumps(
                {
                    "success": True,
                    "data": {
                        "success": True,
                        "task": task,
                        "steps": steps,
                        "done": done,
                        "result": str(final_result) if final_result is not None else None,
                        "urls": urls[:200],
                        "current_url": current_url,
                        "url": current_url,
                    },
                }
            )
        )
    except Exception as exc:
        print(json.dumps({"success": True, "data": {"success": False, "error": str(exc), "task": task}}))
    finally:
        if browser is not None:
            stop = getattr(browser, "stop", None)
            if stop is not None:
                try:
                    maybe = stop()
                    if asyncio.iscoroutine(maybe):
                        await maybe
                except Exception:
                    pass


asyncio.run(main())
"""


class BrowserUseScanner:
    """
    Guarded wrapper for browser-use Python-library automation.

    Notes:
    - Browser execution is allowed only when the Python library can enforce the
      exact-origin boundary through ``Browser.allowed_domains``.
    - Native CLI, named-session, and custom-command paths fail closed because a
      prompt or post-run telemetry check cannot prevent an out-of-scope request.
    - Results are parsed heuristically from stdout/stderr into URLs + finding signals.
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def is_available(self, command_override: Optional[str] = None) -> bool:
        if isinstance(command_override, str) and command_override.strip():
            return False
        return bool(self._resolve_python_binary())

    def prefers_library_run(
        self,
        *,
        command_override: Optional[str] = None,
        explicit_session: Optional[str] = None,
    ) -> bool:
        return self._should_use_library_run(
            session=explicit_session,
            command_override=command_override,
        )

    def _canonical_http_origin(self, value: str) -> Optional[str]:
        """Return a canonical exact HTTP origin suitable for browser-use policy."""
        try:
            parsed = urlparse(str(value or "").strip())
            scheme = str(parsed.scheme or "").strip().lower()
            host = str(parsed.hostname or "").strip().lower()
            port = parsed.port
        except (TypeError, ValueError):
            return None
        if scheme not in {"http", "https"} or not host:
            return None

        display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if scheme == "https" else 80
        port_suffix = f":{int(port)}" if port is not None and int(port) != default_port else ""
        # The trailing slash gives browser-use a full URL prefix instead of an
        # ambiguous hostname prefix (for example, example.test.evil.invalid).
        return f"{scheme}://{display_host}{port_suffix}/"

    def _normalize_allowed_origins(
        self,
        target_url: str,
        allowed_origins: Optional[Sequence[str]],
    ) -> List[str]:
        target_origin = self._canonical_http_origin(target_url)
        if not target_origin:
            raise ValueError("Browser target must contain a valid HTTP origin")

        if allowed_origins is None:
            raw_origins: Sequence[str] = [target_url]
        elif isinstance(allowed_origins, str):
            raw_origins = [allowed_origins]
        else:
            raw_origins = allowed_origins

        normalized: List[str] = []
        for raw in raw_origins:
            origin = self._canonical_http_origin(str(raw or "").strip())
            if not origin:
                raise ValueError(f"Invalid allowed browser origin: {raw!r}")
            if origin not in normalized:
                normalized.append(origin)
        if target_origin not in normalized:
            raise ValueError(
                f"Allowed browser origins must include the target origin {target_origin}"
            )
        return normalized

    def _url_is_allowed(self, value: str, allowed_origins: Sequence[str]) -> bool:
        origin = self._canonical_http_origin(value)
        return bool(origin and origin in set(allowed_origins or []))

    def _task_with_origin_policy(self, task: str, allowed_origins: Sequence[str]) -> str:
        origins = ", ".join(str(origin) for origin in allowed_origins)
        return (
            f"{str(task or '').strip()}\n\n"
            "Mandatory navigation policy: remain within these exact URL origins only: "
            f"{origins}. Do not open or follow cross-origin links, redirects, popups, "
            "iframes, downloads, or authentication handoffs. Stop and report the redirect "
            "instead of leaving the allowed origins."
        )

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
        allow_deterministic_fallback: bool = False,
        deterministic_max_paths: int = 8,
        allowed_origins: Optional[Sequence[str]] = None,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        target_url = str(target or "").strip()
        if not target_url:
            return {"success": False, "error": "No browser target provided", "command": ""}
        if not target_url.startswith(("http://", "https://")):
            return {"success": False, "error": "Browser target must include http:// or https://", "command": ""}

        try:
            origin_policy = self._normalize_allowed_origins(target_url, allowed_origins)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "command": ""}

        steps = max(1, min(int(max_steps or 25), 100))
        task_text = str(task or "").strip()
        if not task_text:
            task_text = (
                f"Open {target_url} and inspect for security-relevant issues, exposed endpoints, "
                "authentication weaknesses, and sensitive data leakage."
            )
        execution_task = self._task_with_origin_policy(task_text, origin_policy)

        use_library_run = self._should_use_library_run(
            session=session,
            command_override=command,
        )
        policy_metadata = {
            "allowed_origins": list(origin_policy),
            "native_enforcement": "browser.allowed_domains" if use_library_run else "unavailable",
            "structured_url_validation": True,
            "deterministic_cli_fallback": "disabled",
        }

        # Kept in the signature for configuration compatibility. The deterministic
        # probe uses native browser-use CLI commands, so it cannot provide the same
        # preventive origin boundary as Browser.allowed_domains.
        if bool(allow_deterministic_fallback):
            logger.warning(
                "Ignoring deprecated browser-use deterministic CLI fallback; "
                "guarded scans require native exact-origin enforcement."
            )
        allow_deterministic_fallback = False

        if not use_library_run:
            if isinstance(command, str) and command.strip():
                error = (
                    "Custom browser-use commands are disabled for guarded scans because "
                    "Supabash cannot verify native exact-origin enforcement."
                )
            elif isinstance(session, str) and session.strip():
                error = (
                    "Named browser-use sessions require the native CLI and are disabled for "
                    "guarded scans because that path cannot enforce exact-origin boundaries."
                )
            else:
                error = (
                    "browser-use Python library runtime with native exact-origin enforcement "
                    "was not found. Install browser-use in an isolated Python environment."
                )
            return {
                "success": False,
                "error": error,
                "command": "",
                "target": target_url,
                "task": task_text,
                "policy_blocked": True,
                "origin_policy": policy_metadata,
            }

        command_list = self._build_library_command(
            task=execution_task,
            max_steps=steps,
            headless=bool(headless),
            model=model,
            profile=profile,
            allowed_origins=origin_policy,
        )
        if not command_list:
            return {
                "success": False,
                "error": (
                    "browser-use runtime not found "
                    "(install browser-use or configure tools.browser_use.command)."
                ),
                "command": "",
            }
        if isinstance(arguments, str) and arguments.strip():
            command_list.extend(shlex.split(arguments))
        display_command = self._describe_command(
            command_list,
            target=target_url,
            task=task_text,
            max_steps=steps,
            headless=bool(headless),
            model=model,
            session=session,
            profile=profile,
            used_library=use_library_run,
        )

        timeout = resolve_timeout_seconds(timeout_seconds, default=900)
        kwargs = {"timeout": timeout}
        if cancel_event is not None:
            kwargs["cancel_event"] = cancel_event

        def _merged_output(cmd_result: CommandResult) -> str:
            return "\n".join(
                x for x in [cmd_result.stdout, cmd_result.stderr] if isinstance(x, str) and x.strip()
            )

        logger.info(f"Starting browser_use scan on {target_url}")
        result: CommandResult = self.runner.run(command_list, **kwargs)
        combined_output = _merged_output(result)
        payload = self._parse_json_payload(combined_output)
        session_retry_attempted = False

        if not result.success:
            err = result.stderr or result.stdout or f"Command failed (RC={result.return_code}): {result.command}"
            if (
                isinstance(session, str)
                and session.strip()
                and not (isinstance(command, str) and command.strip())
                and self._is_socket_timeout_error(err)
            ):
                retry_cmd = self._build_command(
                    target=target_url,
                    task=execution_task,
                    max_steps=steps,
                    headless=bool(headless),
                    model=model,
                    session=None,
                    profile=profile,
                    command_override=command,
                    allowed_origins=origin_policy,
                )
                if retry_cmd:
                    if isinstance(arguments, str) and arguments.strip():
                        retry_cmd.extend(shlex.split(arguments))
                    retry_result: CommandResult = self.runner.run(retry_cmd, **kwargs)
                    session_retry_attempted = True
                    if retry_result.success:
                        result = retry_result
                        combined_output = _merged_output(retry_result)
                        payload = self._parse_json_payload(combined_output)
                    else:
                        retry_err = (
                            retry_result.stderr
                            or retry_result.stdout
                            or f"Command failed (RC={retry_result.return_code}): {retry_result.command}"
                        )
                        err = f"{err}\nRetry without session failed: {retry_err}"
                        combined_output = _merged_output(retry_result)
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
                        allowed_origins=origin_policy,
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
                        "display_command": display_command,
                        "origin_policy": policy_metadata,
                    }
                if isinstance(fallback, dict) and str(fallback.get("error") or "").strip():
                    err = f"{err}\nDeterministic fallback stopped: {str(fallback.get('error')).strip()}"
                return {
                    "success": False,
                    "error": err,
                    "canceled": bool(getattr(result, "canceled", False)),
                    "raw_output": combined_output,
                    "command": result.command,
                    "display_command": display_command,
                }

        status = self._extract_cli_status(combined_output, payload=payload)
        if isinstance(status, dict) and status.get("ok") is False:
            status_error = str(status.get("error") or "browser-use reported unsuccessful run").strip()
            can_retry_without_session = (
                isinstance(session, str)
                and session.strip()
                and not session_retry_attempted
                and not (isinstance(command, str) and command.strip())
                and self._is_session_runtime_compatibility_error(status_error)
            )
            if can_retry_without_session:
                retry_cmd = self._build_command(
                    target=target_url,
                    task=execution_task,
                    max_steps=steps,
                    headless=bool(headless),
                    model=model,
                    session=None,
                    profile=profile,
                    command_override=command,
                    allowed_origins=origin_policy,
                )
                if retry_cmd:
                    if isinstance(arguments, str) and arguments.strip():
                        retry_cmd.extend(shlex.split(arguments))
                    retry_result = self.runner.run(retry_cmd, **kwargs)
                    session_retry_attempted = True
                    if retry_result.success:
                        result = retry_result
                        combined_output = _merged_output(retry_result)
                        payload = self._parse_json_payload(combined_output)
                        status = self._extract_cli_status(combined_output, payload=payload)
                        if not (isinstance(status, dict) and status.get("ok") is False):
                            # Recovery succeeded; continue with normal parsing below.
                            status_error = ""
                    else:
                        retry_err = (
                            retry_result.stderr
                            or retry_result.stdout
                            or f"Command failed (RC={retry_result.return_code}): {retry_result.command}"
                        )
                        status_error = f"{status_error}\nRetry without session failed: {retry_err}"
                        combined_output = _merged_output(retry_result)
                        payload = self._parse_json_payload(combined_output)
                        result = retry_result

            status = self._extract_cli_status(combined_output, payload=payload)
            if isinstance(status, dict) and status.get("ok") is False:
                status_error = str(status.get("error") or status_error or "browser-use reported unsuccessful run").strip()
                fallback: Optional[Dict[str, Any]] = None
                if (
                    bool(allow_deterministic_fallback)
                    and not (isinstance(command, str) and command.strip())
                    and self._is_session_runtime_compatibility_error(status_error)
                ):
                    fallback_session = None if session_retry_attempted else session
                    fallback = self._run_deterministic_probe(
                        target_url=target_url,
                        objective_text=task_text,
                        session=fallback_session,
                        profile=profile,
                        headless=bool(headless),
                        max_paths=int(max(1, min(int(deterministic_max_paths or 8), 24))),
                        allowed_origins=origin_policy,
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
                        "display_command": display_command,
                        "origin_policy": policy_metadata,
                    }
                if isinstance(fallback, dict) and str(fallback.get("error") or "").strip():
                    status_error = (
                        f"{status_error}\nDeterministic fallback stopped: "
                        f"{str(fallback.get('error')).strip()}"
                    )
                return {
                    "success": False,
                    "error": status_error,
                    "canceled": False,
                    "raw_output": combined_output,
                    "command": result.command,
                    "display_command": display_command,
                }

        origin_violations = self._payload_origin_violations(payload, origin_policy)
        if origin_violations:
            return {
                "success": False,
                "error": (
                    "browser-use reported navigation outside the allowed origin policy: "
                    + ", ".join(origin_violations[:5])
                ),
                "canceled": False,
                "target": target_url,
                "task": task_text,
                "raw_output": combined_output,
                "command": result.command,
                "display_command": display_command,
                "origin_policy": policy_metadata,
            }

        parsed = self._parse_output(combined_output, target_url, payload=payload)
        parsed["urls"] = [
            url for url in (parsed.get("urls") or []) if self._url_is_allowed(str(url), origin_policy)
        ] or [target_url]
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
                    allowed_origins=origin_policy,
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
                    "display_command": display_command,
                    "origin_policy": policy_metadata,
                }
            if isinstance(fallback, dict) and str(fallback.get("error") or "").strip():
                completion_error = (
                    f"{completion_error}\nDeterministic fallback stopped: "
                    f"{str(fallback.get('error')).strip()}"
                )
            return {
                "success": False,
                "error": completion_error,
                "canceled": False,
                "target": target_url,
                "task": task_text,
                "observation": completion,
                "raw_output": combined_output,
                "command": result.command,
                "display_command": display_command,
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
            "display_command": display_command,
            "origin_policy": policy_metadata,
        }

    def _is_socket_timeout_error(self, error_text: Any) -> bool:
        text = str(error_text or "").strip().lower()
        if not text:
            return False
        timeout_tokens = ("timed out", "timeouterror", "socket", "recv")
        return any(token in text for token in timeout_tokens)

    def _is_session_runtime_compatibility_error(self, error_text: Any) -> bool:
        text = str(error_text or "").strip().lower()
        if not text:
            return False
        if "chatbrowseruse" in text and "await" in text:
            return True
        compatibility_tokens = (
            "can't be used in 'await' expression",
            'can\'t be used in "await" expression',
            "await expression",
            "object chatbrowseruse",
        )
        return any(token in text for token in compatibility_tokens)

    def _should_use_library_run(
        self,
        *,
        session: Optional[str],
        command_override: Optional[str],
    ) -> bool:
        if isinstance(command_override, str) and command_override.strip():
            return False
        if isinstance(session, str) and session.strip():
            return False
        return bool(self._resolve_python_binary())

    def _resolve_cli_binary(self) -> Optional[str]:
        for candidate in ("browser-use", "browser_use"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    def _resolve_python_binary(self) -> Optional[str]:
        binary = self._resolve_cli_binary()
        if not binary:
            return None
        try:
            real_binary = os.path.realpath(binary)
        except Exception:
            real_binary = binary
        if not os.path.isfile(real_binary):
            return None

        try:
            with open(real_binary, "r", encoding="utf-8", errors="ignore") as handle:
                first_line = str(handle.readline() or "").strip()
        except Exception:
            first_line = ""

        if first_line.startswith("#!"):
            shebang = first_line[2:].strip().split()[0].strip()
            if shebang and os.path.isfile(shebang) and os.access(shebang, os.X_OK):
                return shebang

        bin_dir = os.path.dirname(real_binary)
        for candidate in ("python", "python3"):
            interpreter = os.path.join(bin_dir, candidate)
            if os.path.isfile(interpreter) and os.access(interpreter, os.X_OK):
                return interpreter
        return None

    def _build_library_command(
        self,
        *,
        task: str,
        max_steps: int,
        headless: bool,
        model: Optional[str],
        profile: Optional[str],
        allowed_origins: Optional[Sequence[str]] = None,
    ) -> Optional[List[str]]:
        python_binary = self._resolve_python_binary()
        if not python_binary:
            return None
        return [
            python_binary,
            "-c",
            _BROWSER_USE_LIBRARY_RUNNER,
            str(task or "").strip(),
            str(int(max_steps)),
            "1" if headless else "0",
            str(model or "").strip(),
            str(profile or "").strip(),
            json.dumps(list(allowed_origins or []), separators=(",", ":")),
        ]

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
        allowed_origins: Optional[Sequence[str]] = None,
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
                "allowed_origins": ",".join(str(x) for x in (allowed_origins or [])),
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

    def _describe_command(
        self,
        command_list: List[str],
        *,
        target: str,
        task: str,
        max_steps: int,
        headless: bool,
        model: Optional[str],
        session: Optional[str],
        profile: Optional[str],
        used_library: bool,
    ) -> str:
        parts: List[str] = []
        if target:
            parts.append(f"target={target}")
        parts.append(f"max_steps={int(max_steps)}")
        parts.append(f"headless={'true' if headless else 'false'}")
        if model:
            parts.append(f"model={str(model).strip()}")
        if profile:
            parts.append(f"profile={str(profile).strip()}")
        if session:
            parts.append(f"session={str(session).strip()}")
        task_line = re.sub(r"\s+", " ", str(task or "").strip().splitlines()[0]).strip() if str(task or "").strip() else ""
        if task_line:
            if len(task_line) > 88:
                task_line = f"{task_line[:85].rstrip()}..."
            parts.append(f'task="{task_line}"')
        if used_library:
            return f"browser_use.run({', '.join(parts)})"

        tokens = [str(x or "").strip() for x in (command_list or [])]
        lowered = [x.lower() for x in tokens]
        if "open" in lowered:
            try:
                url = tokens[lowered.index("open") + 1]
            except Exception:
                url = target
            return f"browser_use.open(url={url or target})"
        if "get" in lowered:
            try:
                kind = tokens[lowered.index("get") + 1]
            except Exception:
                kind = "unknown"
            return f"browser_use.get(kind={kind})"
        if "state" in lowered:
            return "browser_use.state()"
        if "close" in lowered:
            return "browser_use.close(all=true)" if "--all" in lowered else "browser_use.close()"
        return f"browser_use.run({', '.join(parts)})"

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

    def _payload_navigation_urls(self, payload: Optional[Dict[str, Any]]) -> List[str]:
        """Extract only structured navigation telemetry, not URLs mentioned in prose."""
        if not isinstance(payload, dict):
            return []
        containers: List[Dict[str, Any]] = [payload]
        data = payload.get("data")
        if isinstance(data, dict):
            containers.insert(0, data)

        urls: List[str] = []
        seen: Set[str] = set()
        for container in containers:
            values: List[Any] = []
            raw_urls = container.get("urls")
            if isinstance(raw_urls, (list, tuple)):
                values.extend(raw_urls)
            values.extend([container.get("current_url"), container.get("url")])
            for raw in values:
                candidate = self._strip_trailing_url_artifacts(str(raw or "").strip())
                try:
                    scheme = str(urlparse(candidate).scheme or "").lower()
                except Exception:
                    continue
                if scheme not in {"http", "https"} or candidate in seen:
                    continue
                seen.add(candidate)
                urls.append(candidate)
        return urls

    def _payload_origin_violations(
        self,
        payload: Optional[Dict[str, Any]],
        allowed_origins: Sequence[str],
    ) -> List[str]:
        return [
            url
            for url in self._payload_navigation_urls(payload)
            if not self._url_is_allowed(url, allowed_origins)
        ]

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
                url_list = data.get("urls")
                if isinstance(url_list, list):
                    for raw in url_list:
                        candidate = self._sanitize_extracted_url(
                            str(raw or "").strip(),
                            parsed_base=parsed_target,
                        )
                        if not candidate or candidate in seen:
                            continue
                        seen.add(candidate)
                        out.append(candidate)
                        if len(out) >= 200:
                            break
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
        structured = self._extract_structured_findings(text, target=target)
        if structured:
            return structured[:120]

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

    def _extract_structured_findings(self, text: str, *, target: str) -> List[Dict[str, Any]]:
        body = str(text or "").strip()
        if not body:
            return []

        findings: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        try:
            parsed_target = urlparse(str(target or "").strip())
        except Exception:
            parsed_target = None

        def append_structured(*, severity: str, title: str, evidence: str, confidence: str = "high") -> None:
            self._append_browser_finding(
                findings,
                seen,
                severity=severity,
                title=title,
                evidence=self._sanitize_urls_in_text(str(evidence or "").strip(), parsed_base=parsed_target),
                confidence=confidence,
            )

        lines = [str(line or "") for line in body.splitlines()]
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            endpoint_match = re.match(r"^\s*-\s*\*\*Endpoint:\*\*\s*`?([^`]+)`?\s*$", line)
            if endpoint_match:
                endpoint = self._sanitize_extracted_url(
                    endpoint_match.group(1).strip(),
                    parsed_base=parsed_target,
                ) or endpoint_match.group(1).strip()
                status_code: Optional[int] = None
                observation_parts: List[str] = []
                j = i + 1
                while j < len(lines):
                    next_line = lines[j].rstrip()
                    if re.match(r"^\s*-\s*\*\*Endpoint:\*\*", next_line):
                        break
                    if re.match(r"^\s*\*\*Conclusion:\*\*", next_line):
                        break
                    status_match = re.match(r"^\s*-\s*\*\*Status:\*\*\s*HTTP\s+(\d+)", next_line, flags=re.IGNORECASE)
                    if status_match:
                        try:
                            status_code = int(status_match.group(1))
                        except Exception:
                            status_code = None
                        j += 1
                        continue
                    observation_match = re.match(
                        r"^\s*-\s*\*\*Observations:\*\*\s*(.+)$",
                        next_line,
                        flags=re.IGNORECASE,
                    )
                    if observation_match:
                        observation_parts.append(observation_match.group(1).strip())
                        j += 1
                        while j < len(lines):
                            continuation = lines[j].rstrip()
                            if not continuation.strip():
                                j += 1
                                continue
                            if re.match(r"^\s*-\s*\*\*", continuation) or re.match(r"^\s*\*\*Conclusion:\*\*", continuation):
                                break
                            observation_parts.append(continuation.strip())
                            j += 1
                        continue
                    j += 1

                title, severity = self._classify_structured_endpoint_observation(endpoint, observation_parts)
                status_fragment = f"(HTTP {status_code}) " if status_code is not None else ""
                evidence = f"{endpoint} {status_fragment}{' '.join(part for part in observation_parts if part).strip()}".strip()
                append_structured(severity=severity, title=title, evidence=evidence or endpoint)
                i = j
                continue

            bullet_match = re.match(r"^\s*-\s*\[([A-Z/]+)\]\s*(.+)$", line)
            if bullet_match:
                severity = self._pick_highest_severity(bullet_match.group(1))
                body_text = bullet_match.group(2).strip()
                evidence_parts = [line.strip()]
                j = i + 1
                while j < len(lines):
                    continuation = lines[j].rstrip()
                    if not continuation.strip():
                        break
                    if re.match(r"^\s*-\s*\[([A-Z/]+)\]\s*", continuation):
                        break
                    if re.match(r"^\s*-\s*\*\*Endpoint:\*\*", continuation):
                        break
                    if re.match(r"^\s*\*\*Conclusion:\*\*", continuation):
                        break
                    if continuation.startswith("  ") or continuation.startswith("\t"):
                        evidence_parts.append(continuation.strip())
                        j += 1
                        continue
                    break
                for finding in self._expand_structured_bullet_finding(body_text, severity, evidence_parts, parsed_target):
                    append_structured(
                        severity=str(finding.get("severity") or severity),
                        title=str(finding.get("title") or body_text),
                        evidence=str(finding.get("evidence") or " ".join(evidence_parts)),
                        confidence=str(finding.get("confidence") or "high"),
                    )
                i = j
                continue
            i += 1
        return findings

    def _pick_highest_severity(self, label: str) -> str:
        parts = [str(x or "").strip().upper() for x in str(label or "").split("/") if str(x or "").strip()]
        if not parts:
            return "INFO"
        best = "INFO"
        best_rank = _BROWSER_USE_FINDING_SEVERITY_RANK.get(best, 1)
        for part in parts:
            rank = _BROWSER_USE_FINDING_SEVERITY_RANK.get(part, 1)
            if rank > best_rank:
                best = part
                best_rank = rank
        return best

    def _normalize_structured_bullet_title(self, title: str, evidence_low: str, severity: str) -> str:
        raw = str(title or "").strip().rstrip(".")
        low = raw.lower()
        if "supabase keys exposed in home page source" in low and "service_role_key" in evidence_low:
            return "Supabase service role key exposed"
        if "unauthenticated access to supabase rest api" in low:
            return "Supabase REST API accessible without authentication"
        if "unauthenticated access to supabase rpc endpoint" in low:
            return "Supabase RPC endpoint exposed without authentication"
        if "unauthenticated execution of" in low and "list_users" in low:
            return "Supabase RPC 'list_users' callable without authentication"
        if "potential rls bypass confirmed" in low:
            return "Supabase RLS may be disabled"
        if "anonymous s3-compatible bucket listing" in low:
            return "Anonymous S3-compatible bucket listing accessible"
        if "unauthenticated metrics endpoint" in low:
            return "Unauthenticated metrics endpoint accessible"
        if "pprof debug endpoint" in low:
            return "Go pprof debug endpoint accessible without authentication"
        if "config endpoint" in low and "prometheus" in low:
            return "Prometheus config endpoint accessible without authentication"
        if "configuration exposure" in low and severity == "HIGH":
            return "Unauthenticated configuration exposure verified in browser workflow"
        return raw

    def _expand_structured_bullet_finding(
        self,
        body_text: str,
        severity: str,
        evidence_parts: List[str],
        parsed_target,
    ) -> List[Dict[str, Any]]:
        title_text, _, detail_text = str(body_text or "").partition(":")
        title = str(title_text or "").strip().rstrip(".")
        detail = str(detail_text or "").strip()
        evidence = " ".join(str(x or "").strip() for x in evidence_parts if str(x or "").strip())
        evidence = self._sanitize_urls_in_text(evidence, parsed_base=parsed_target)
        evidence_low = evidence.lower()

        findings: List[Dict[str, Any]] = []
        if "supabase keys exposed in home page source" in title.lower():
            if "service_role_key" in evidence_low:
                findings.append(
                    {
                        "severity": "CRITICAL",
                        "title": "Supabase service role key exposed",
                        "evidence": evidence,
                        "confidence": "high",
                    }
                )
            if "anon_key" in evidence_low:
                findings.append(
                    {
                        "severity": "LOW",
                        "title": "Supabase anon key exposed in client content",
                        "evidence": evidence,
                        "confidence": "high",
                    }
                )
            if findings:
                return findings

        normalized_title = self._normalize_structured_bullet_title(title or body_text, evidence_low, severity)
        normalized_evidence = evidence
        if detail:
            normalized_evidence = self._sanitize_urls_in_text(
                f"{normalized_title}: {detail}",
                parsed_base=parsed_target,
            )
        return [
            {
                "severity": severity,
                "title": normalized_title,
                "evidence": normalized_evidence,
                "confidence": "high" if severity in {"CRITICAL", "HIGH"} else "medium",
            }
        ]

    def _classify_structured_endpoint_observation(
        self,
        endpoint: str,
        observation_parts: List[str],
    ) -> tuple[str, str]:
        low = " ".join(str(x or "").lower() for x in observation_parts)
        try:
            parsed = urlparse(str(endpoint or "").strip())
        except Exception:
            parsed = None
        path = str(parsed.path or "/").lower() if parsed is not None else ""
        if "/api/v1/status/config" in path:
            return "Prometheus config endpoint accessible without authentication", "HIGH"
        if "/api/v1/status/flags" in path:
            return "Prometheus flags endpoint accessible without authentication", "MEDIUM"
        if "/api/v1/targets" in path:
            return "Prometheus targets endpoint accessible without authentication", "MEDIUM"
        if "/api/v1/status/runtimeinfo" in path:
            return "Prometheus runtimeinfo endpoint accessible without authentication", "MEDIUM"
        if path.endswith("/metrics"):
            return "Unauthenticated metrics endpoint accessible", "MEDIUM"
        if "/rest/v1/rpc/list_users" in path:
            return "Supabase RPC 'list_users' callable without authentication", "HIGH"
        if "/rest/v1/rpc/" in path:
            return "Supabase RPC endpoint exposed without authentication", "MEDIUM"
        if "/rest/v1" in path:
            return "Supabase REST API accessible without authentication", "HIGH"
        if "scrape_configs" in low or "configuration" in low:
            return "Unauthenticated configuration exposure verified in browser workflow", "HIGH"
        if "targets" in low or "runtime" in low or "flags" in low:
            return f"Endpoint accessible without authentication: {path or '/'}", "MEDIUM"
        return f"Endpoint accessible without authentication: {path or '/'}", "MEDIUM"

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
        allowed_origins: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        binary = self._resolve_cli_binary()
        if not binary:
            return {"success": False, "error": "browser-use CLI not found for deterministic probe"}
        try:
            origin_policy = self._normalize_allowed_origins(target_url, allowed_origins)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

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
        probe_timeout = min(5, max(2, int(timeout)))
        root_preflight = self._preflight_navigation(
            target_url,
            allowed_origins=origin_policy,
            timeout_seconds=probe_timeout,
        )
        if not root_preflight.get("success"):
            return {
                "success": False,
                "error": str(root_preflight.get("error") or "Origin policy stopped target navigation"),
                "steps": probe_steps,
                "origin_policy": {"allowed_origins": list(origin_policy)},
            }
        root_navigation_url = str(root_preflight.get("effective_url") or target_url).strip()
        focus_urls = self._extract_task_focus_urls(
            root_navigation_url,
            objective_text or "",
            max_urls=max(2, min(int(max_paths), 24)),
        )
        focus_url_set = set(focus_urls)

        open_root = self._run_cli_json(
            base_cmd + ["open", root_navigation_url],
            cancel_event=cancel_event,
            timeout=timeout,
        )
        probe_steps += 1
        if not open_root.get("success"):
            return {
                "success": False,
                "error": str(open_root.get("error") or "Deterministic probe could not open target"),
                "steps": probe_steps,
            }
        open_violations = self._payload_origin_violations(open_root.get("payload"), origin_policy)
        if open_violations:
            return {
                "success": False,
                "error": (
                    "Origin policy stopped deterministic navigation after browser telemetry "
                    f"reported {open_violations[0]}"
                ),
                "steps": probe_steps,
            }
        visited_urls.append(root_navigation_url)

        state_payload = self._run_cli_json(base_cmd + ["state"], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        state_violations = self._payload_origin_violations(state_payload.get("payload"), origin_policy)
        if state_violations:
            return {
                "success": False,
                "error": (
                    "Origin policy stopped deterministic navigation after browser state "
                    f"reported {state_violations[0]}"
                ),
                "steps": probe_steps,
            }
        title_payload = self._run_cli_json(base_cmd + ["get", "title"], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        html_payload = self._run_cli_json(base_cmd + ["get", "html"], cancel_event=cancel_event, timeout=timeout)
        probe_steps += 1
        root_html = str(self._extract_text_from_payload(html_payload.get("payload")) or "").strip()
        if root_html:
            html_cache[root_navigation_url] = root_html
            meaningful_artifacts += 1

        root_title = str(self._extract_text_from_payload(title_payload.get("payload")) or "").strip()
        if root_title:
            meaningful_artifacts += 1
            self._append_browser_finding(
                findings,
                seen_findings,
                severity="INFO",
                title="Browser page title observed",
                evidence=f"{root_navigation_url} title={root_title[:180]}",
                confidence="low",
            )

        root_response = root_preflight.get("response") if isinstance(root_preflight.get("response"), dict) else {}
        root_status = root_response.get("status")
        root_body = root_response.get("body")
        root_content_type = str(root_response.get("content_type") or "")
        added = self._extract_response_signals(
            root_navigation_url,
            status=root_status,
            body=root_body,
            content_type=root_content_type,
            findings=findings,
            seen_findings=seen_findings,
        )
        if added > 0:
            meaningful_artifacts += int(added)
            if root_navigation_url in focus_url_set:
                focused_endpoint_artifacts += int(added)

        candidates = self._derive_probe_urls(
            root_navigation_url,
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
            candidate_preflight = self._preflight_navigation(
                candidate,
                allowed_origins=origin_policy,
                timeout_seconds=probe_timeout,
            )
            if not candidate_preflight.get("success"):
                self._append_browser_finding(
                    findings,
                    seen_findings,
                    severity="INFO",
                    title="Redirect blocked by navigation policy",
                    evidence=str(candidate_preflight.get("error") or f"Navigation to {candidate} was blocked."),
                    confidence="high",
                )
                continue
            effective_candidate = str(candidate_preflight.get("effective_url") or candidate).strip()
            is_focus_candidate = candidate in focus_url_set or effective_candidate in focus_url_set
            open_out = self._run_cli_json(
                base_cmd + ["open", effective_candidate],
                cancel_event=cancel_event,
                timeout=timeout,
            )
            probe_steps += 1
            if not open_out.get("success"):
                continue
            open_violations = self._payload_origin_violations(open_out.get("payload"), origin_policy)
            if open_violations:
                return {
                    "success": False,
                    "error": (
                        "Origin policy stopped deterministic navigation after browser telemetry "
                        f"reported {open_violations[0]}"
                    ),
                    "steps": probe_steps,
                }
            if is_focus_candidate:
                focus_hits += 1
            if effective_candidate not in visited_urls:
                visited_urls.append(effective_candidate)
            title_out = self._run_cli_json(base_cmd + ["get", "title"], cancel_event=cancel_event, timeout=timeout)
            probe_steps += 1
            page_title = str(self._extract_text_from_payload(title_out.get("payload")) or "").strip()
            if page_title:
                meaningful_artifacts += 1
                if is_focus_candidate:
                    focused_endpoint_artifacts += 1
                    self._append_browser_finding(
                        findings,
                        seen_findings,
                        severity="MEDIUM",
                        title="Focused endpoint rendered in browser workflow",
                        evidence=(
                            f"{effective_candidate} rendered a browser page without explicit pre-auth steps; "
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
                        evidence=f"{effective_candidate} title={page_title[:180]}",
                        confidence="medium",
                    )
            html_out = self._run_cli_json(base_cmd + ["get", "html"], cancel_event=cancel_event, timeout=timeout)
            probe_steps += 1
            page_html = str(self._extract_text_from_payload(html_out.get("payload")) or "").strip()
            if page_html:
                html_cache[effective_candidate] = page_html
                meaningful_artifacts += 1
                if is_focus_candidate:
                    focused_endpoint_artifacts += 1
            candidate_response = (
                candidate_preflight.get("response")
                if isinstance(candidate_preflight.get("response"), dict)
                else {}
            )
            response_status = candidate_response.get("status")
            response_body = candidate_response.get("body")
            response_content_type = str(candidate_response.get("content_type") or "")
            added = self._extract_response_signals(
                effective_candidate,
                status=response_status,
                body=response_body,
                content_type=response_content_type,
                findings=findings,
                seen_findings=seen_findings,
            )
            if added > 0:
                meaningful_artifacts += int(added)
                if is_focus_candidate:
                    focused_endpoint_artifacts += int(added)

        for u, html in list(html_cache.items()):
            self._extract_html_signals(u, html, findings, seen_findings)
        if not html_cache and root_html:
            self._extract_html_signals(root_navigation_url, root_html, findings, seen_findings)
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

    def _looks_html_document(self, value: str) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return False
        return any(token in text for token in ("<!doctype html", "<html", "<body", "<form", "<a ", "<div"))

    def _target_is_deep_api_like(self, value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        try:
            parsed = urlparse(text)
        except Exception:
            return False
        path = str(parsed.path or "").strip()
        if not path or path == "/":
            return False
        segments = [seg.strip().lower() for seg in path.split("/") if seg.strip()]
        if not segments:
            return False
        api_markers = {
            "api",
            "apis",
            "rest",
            "rpc",
            "graphql",
            "graphiql",
            "actuator",
            "metrics",
            "swagger",
            "swagger-ui",
            "openapi",
            "v1",
            "v2",
            "v3",
        }
        if any(seg in api_markers for seg in segments):
            return True
        if len(segments) >= 3:
            return True
        query = str(parsed.query or "").strip().lower()
        return any(token in query for token in ("format=json", "format=xml", "schema=", "table="))

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

        html_like = self._looks_html_document(root_html)
        deep_api_target = self._target_is_deep_api_like(base_url)
        allow_seed_paths = (not deep_api_target) and (html_like or not base_path_prefix)
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
        details = self._http_probe_details(url, timeout_seconds=timeout_seconds)
        return (
            details.get("status"),
            details.get("body"),
            str(details.get("content_type") or ""),
            details.get("error"),
        )

    def _http_probe_details(
        self,
        url: str,
        *,
        timeout_seconds: int = 5,
    ) -> Dict[str, Any]:
        """Fetch one HTTP response without following redirects."""
        request = Request(url, headers={"User-Agent": "supabash-browser-use-fallback/1.0"})
        try:
            opener = build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=max(1, int(timeout_seconds))) as response:
                status = int(response.getcode())
                content_type = str(response.headers.get("Content-Type") or "").strip()
                location = str(response.headers.get("Location") or "").strip() or None
                body = response.read(4096).decode("utf-8", errors="ignore")
                return {
                    "status": status,
                    "body": body,
                    "content_type": content_type,
                    "location": location,
                    "error": None,
                }
        except HTTPError as e:
            status = int(getattr(e, "code", 0) or 0) or None
            headers = getattr(e, "headers", None)
            content_type = str((headers.get("Content-Type") if headers is not None else "") or "").strip()
            location = str((headers.get("Location") if headers is not None else "") or "").strip() or None
            body = ""
            try:
                body = (e.read() or b"").decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return {
                "status": status,
                "body": body,
                "content_type": content_type,
                "location": location,
                "error": None,
            }
        except (URLError, TimeoutError, OSError) as e:
            return {
                "status": None,
                "body": None,
                "content_type": "",
                "location": None,
                "error": str(e),
            }
        except Exception as e:
            return {
                "status": None,
                "body": None,
                "content_type": "",
                "location": None,
                "error": str(e),
            }

    def _preflight_navigation(
        self,
        url: str,
        *,
        allowed_origins: Sequence[str],
        timeout_seconds: int,
        max_redirects: int = 5,
    ) -> Dict[str, Any]:
        """Resolve same-origin HTTP redirects before a deterministic browser open."""
        current = str(url or "").strip()
        seen: Set[str] = set()
        redirect_chain: List[str] = []
        redirect_statuses = {301, 302, 303, 307, 308}

        for redirect_count in range(max(0, int(max_redirects)) + 1):
            if not self._url_is_allowed(current, allowed_origins):
                return {
                    "success": False,
                    "error": f"Origin policy blocked navigation to {current}",
                    "blocked_url": current,
                    "redirect_chain": redirect_chain,
                }
            if current in seen:
                return {
                    "success": False,
                    "error": f"Redirect loop detected before navigation at {current}",
                    "blocked_url": current,
                    "redirect_chain": redirect_chain,
                }
            seen.add(current)

            response = self._http_probe_details(current, timeout_seconds=timeout_seconds)
            status = response.get("status")
            if status not in redirect_statuses:
                return {
                    "success": True,
                    "effective_url": current,
                    "response": response,
                    "redirect_chain": redirect_chain,
                    "verified": status is not None,
                }

            location = str(response.get("location") or "").strip()
            if not location:
                return {
                    "success": False,
                    "error": f"HTTP {int(status)} redirect from {current} had no Location header",
                    "blocked_url": current,
                    "redirect_chain": redirect_chain,
                }
            if redirect_count >= max(0, int(max_redirects)):
                return {
                    "success": False,
                    "error": f"Redirect limit exceeded before navigation from {url}",
                    "blocked_url": current,
                    "redirect_chain": redirect_chain,
                }

            redirected = urljoin(current, location)
            if not self._url_is_allowed(redirected, allowed_origins):
                return {
                    "success": False,
                    "error": (
                        f"Origin policy blocked cross-origin redirect from {current} "
                        f"to {redirected}"
                    ),
                    "blocked_url": redirected,
                    "redirect_chain": redirect_chain + [redirected],
                }
            redirect_chain.append(redirected)
            current = redirected

        return {
            "success": False,
            "error": f"Redirect validation failed before navigation to {url}",
            "blocked_url": current,
            "redirect_chain": redirect_chain,
        }

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
