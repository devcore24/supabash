import re
import shlex
import shutil
from typing import Any, Dict, List, Optional

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
        arguments: Optional[str] = None,
        command: Optional[str] = None,
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

        if not result.success:
            err = result.stderr or result.stdout or f"Command failed (RC={result.return_code}): {result.command}"
            return {
                "success": False,
                "error": err,
                "canceled": bool(getattr(result, "canceled", False)),
                "raw_output": combined_output,
                "command": result.command,
            }

        parsed = self._parse_output(combined_output, target_url)
        return {
            "success": True,
            "target": target_url,
            "task": task_text,
            "urls": parsed.get("urls", []),
            "findings": parsed.get("findings", []),
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
        command_override: Optional[str],
    ) -> Optional[List[str]]:
        if isinstance(command_override, str) and command_override.strip():
            fmt_values = {
                "target": target,
                "task": task,
                "max_steps": int(max_steps),
                "headless": "true" if headless else "false",
                "model": str(model or "").strip(),
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

        command = [binary, "run", task, "--max-steps", str(int(max_steps))]
        if headless:
            command.append("--headless")
        if isinstance(model, str) and model.strip():
            command.extend(["--model", model.strip()])
        return command

    def _parse_output(self, output: str, target: str) -> Dict[str, Any]:
        text = str(output or "")
        urls = self._extract_urls(text, target=target)
        findings = self._extract_findings(text)
        return {"urls": urls, "findings": findings}

    def _extract_urls(self, text: str, *, target: str) -> List[str]:
        out: List[str] = []
        seen = set()
        for m in re.finditer(r"https?://[^\s'\"<>`]+", text or "", flags=re.IGNORECASE):
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
