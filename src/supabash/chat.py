import json
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    MasscanScanner,
    RustscanScanner,
)
from supabash.audit import AuditOrchestrator
from supabash.llm import LLMClient
from supabash import prompts
from supabash.agent import AgentState, MethodologyPlanner
from supabash.safety import is_allowed_target, ensure_consent, is_public_ip_target
from supabash.llm_context import prepare_json_payload

logger = setup_logger(__name__)


@dataclass
class ChatSession:
    scanners: Dict[str, Any] = field(default_factory=lambda: {
        "nmap": NmapScanner(),
        "masscan": MasscanScanner(),
        "rustscan": RustscanScanner(),
    })
    last_scan_result: Optional[Dict[str, Any]] = None
    last_scan_tool: Optional[str] = None
    last_audit_report: Optional[Dict[str, Any]] = None
    last_result_kind: Optional[str] = None  # "scan" | "audit"
    llm: LLMClient = field(default_factory=LLMClient)
    planner: MethodologyPlanner = field(default_factory=MethodologyPlanner)
    allowed_hosts: List[str] = field(default_factory=list)
    config_manager: Any = None
    last_llm_meta: Optional[Dict[str, Any]] = None
    last_clarifier: Optional[Dict[str, Any]] = None
    audit_orchestrator_factory: Any = None

    def run_scan(
        self,
        target: str,
        profile: str = "fast",
        scanner_name: str = "nmap",
        allow_public: bool = False,
    ) -> Dict[str, Any]:
        scanner_name = scanner_name.lower()
        if scanner_name not in self.scanners:
            return {"success": False, "error": f"Unknown scanner '{scanner_name}'"}

        if self.allowed_hosts and not is_allowed_target(target, self.allowed_hosts):
            return {"success": False, "error": f"Target '{target}' not in allowed_hosts. Edit config.yaml to permit."}

        allow_public_cfg = False
        if self.config_manager is not None:
            allow_public_cfg = bool(self.config_manager.config.get("core", {}).get("allow_public_ips", False))
        if is_public_ip_target(target) and not (allow_public_cfg or allow_public):
            return {
                "success": False,
                "error": "Refusing to scan public IP targets by default. Set core.allow_public_ips=true in config.yaml or pass --allow-public.",
            }

        if not ensure_consent(self.config_manager):
            return {"success": False, "error": "Consent not confirmed"}

        scanner = self.scanners[scanner_name]
        ports = None
        args = None
        extra = {}

        if scanner_name == "nmap":
            args = "-sV -O"
            if profile == "fast":
                args += " -F"
            elif profile == "full":
                ports = "1-65535"
                args += " -T4"
            elif profile == "stealth":
                args = "-sS -T2"
            result = scanner.scan(target, ports=ports, arguments=args)
        elif scanner_name == "masscan":
            ports = "1-1000"
            rate = 1000
            if profile == "full":
                ports = "1-65535"
                rate = 5000
            elif profile == "stealth":
                rate = 100
            result = scanner.scan(target, ports=ports, rate=rate, arguments=args)
        else:  # rustscan
            ports = "1-1000"
            batch = 2000
            if profile == "full":
                ports = "1-65535"
                batch = 5000
            elif profile == "stealth":
                batch = 1000
            result = scanner.scan(target, ports=ports, batch=batch, arguments=args)

        self.last_scan_result = result
        self.last_scan_tool = scanner_name
        self.last_result_kind = "scan"
        return result

    def run_audit(
        self,
        target: str,
        *,
        container_image: Optional[str] = None,
        mode: str = "normal",
        nuclei_rate_limit: int = 0,
        gobuster_threads: int = 10,
        gobuster_wordlist: Optional[str] = None,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        allow_public: bool = False,
        output: Optional[Path] = None,
        markdown: Optional[Path] = None,
    ) -> Dict[str, Any]:
        if self.allowed_hosts and not is_allowed_target(target, self.allowed_hosts):
            return {"success": False, "error": f"Target '{target}' not in allowed_hosts. Edit config.yaml to permit."}

        allow_public_cfg = False
        if self.config_manager is not None:
            allow_public_cfg = bool(self.config_manager.config.get("core", {}).get("allow_public_ips", False))
        if is_public_ip_target(target) and not (allow_public_cfg or allow_public):
            return {
                "success": False,
                "error": "Refusing to scan public IP targets by default. Set core.allow_public_ips=true in config.yaml or pass --allow-public.",
            }

        if mode not in ("normal", "stealth", "aggressive"):
            return {"success": False, "error": "Invalid mode. Choose: normal|stealth|aggressive"}

        if not ensure_consent(self.config_manager):
            return {"success": False, "error": "Consent not confirmed"}

        orchestrator = self.audit_orchestrator_factory() if callable(self.audit_orchestrator_factory) else AuditOrchestrator()
        report = orchestrator.run(
            target,
            output,
            container_image=container_image,
            mode=mode,
            nuclei_rate_limit=nuclei_rate_limit,
            gobuster_threads=gobuster_threads,
            gobuster_wordlist=gobuster_wordlist,
            remediate=remediate,
            max_remediations=max_remediations,
            min_remediation_severity=min_remediation_severity,
        )
        self.last_audit_report = report
        self.last_result_kind = "audit"

        if markdown is not None:
            try:
                from supabash.report import write_markdown
                md_path = write_markdown(report, markdown)
                report.setdefault("_chat", {})["markdown_saved_to"] = md_path
            except Exception as e:
                report.setdefault("_chat", {})["markdown_error"] = str(e)

        return report

    def get_audit_tool_result(self, tool_name: str) -> Optional[Dict[str, Any]]:
        if not self.last_audit_report:
            return None
        tool_name = (tool_name or "").strip().lower()
        if not tool_name:
            return None
        for entry in self.last_audit_report.get("results", []):
            if isinstance(entry, dict) and str(entry.get("tool", "")).lower() == tool_name:
                return entry
        return None

    def save_report(self, path: Path, kind: Optional[str] = None) -> Dict[str, Any]:
        kind = (kind or self.last_result_kind or "").lower()
        if kind == "audit":
            data = self.last_audit_report
        else:
            data = self.last_scan_result
        if not data:
            return {"success": False, "error": "No results to save."}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            return {"success": True, "path": str(path)}
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return {"success": False, "error": str(e)}

    def run_tests(self, workdir: Optional[Path] = None) -> Dict[str, Any]:
        cmd = [self._python_executable(), "-m", "unittest", "discover", "-s", "tests"]
        try:
            result = subprocess.run(
                cmd,
                cwd=str(workdir) if workdir else None,
                capture_output=True,
                text=True,
                timeout=900,
            )
            return {
                "success": result.returncode == 0,
                "return_code": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        except Exception as e:
            logger.error(f"Failed to run tests: {e}")
            return {"success": False, "error": str(e)}

    def _python_executable(self) -> str:
        return subprocess.run(
            ["which", "python"],
            capture_output=True,
            text=True,
        ).stdout.strip() or "python"

    def summarize_findings(self) -> Optional[str]:
        if not self.last_scan_result:
            return None
        try:
            payload = {
                "tool": self.last_scan_tool,
                "result": self.last_scan_result,
            }
            max_chars = 12000
            try:
                cfg = self.config_manager
                if cfg is not None and hasattr(cfg, "config"):
                    max_chars = int(cfg.config.get("llm", {}).get("max_input_chars", max_chars))
            except Exception:
                pass
            content, truncated = prepare_json_payload(payload, max_chars=max_chars)
            messages = [
                {"role": "system", "content": prompts.ANALYZER_PROMPT},
                {"role": "user", "content": content},
            ]
            if truncated:
                messages.insert(1, {"role": "system", "content": "Note: Tool output was truncated to fit context limits."})
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                result = chat_with_meta(messages)
                if isinstance(result, tuple) and len(result) == 2:
                    resp, meta = result
                    if meta is not None:
                        meta = dict(meta)
                        meta.update(
                            {"input_truncated": bool(truncated), "input_chars": len(content), "max_input_chars": int(max_chars)}
                        )
                    self.last_llm_meta = meta
                    return resp
            self.last_llm_meta = None
            return self.llm.chat(messages)
        except Exception as e:
            logger.error(f"LLM summary failed: {e}")
            return None

    def remediate(self, title: str, evidence: str = "", severity: str = "") -> Optional[str]:
        try:
            finding = {"title": title, "evidence": evidence, "severity": severity}
            max_chars = 12000
            try:
                cfg = self.config_manager
                if cfg is not None and hasattr(cfg, "config"):
                    max_chars = int(cfg.config.get("llm", {}).get("max_input_chars", max_chars))
            except Exception:
                pass
            content, truncated = prepare_json_payload(finding, max_chars=max_chars)
            messages = [
                {"role": "system", "content": prompts.REMEDIATOR_PROMPT},
                {"role": "user", "content": content},
            ]
            if truncated:
                messages.insert(1, {"role": "system", "content": "Note: Input was truncated to fit context limits."})
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                result = chat_with_meta(messages)
                if isinstance(result, tuple) and len(result) == 2:
                    resp, meta = result
                    if meta is not None:
                        meta = dict(meta)
                        meta.update(
                            {"input_truncated": bool(truncated), "input_chars": len(content), "max_input_chars": int(max_chars)}
                        )
                    self.last_llm_meta = meta
                    return resp
            self.last_llm_meta = None
            return self.llm.chat(messages)
        except Exception as e:
            logger.error(f"LLM remediation failed: {e}")
            return None

    def plan_next(self) -> Dict[str, Any]:
        if not self.last_scan_result:
            return {"next_steps": [], "notes": "No scan results yet."}
        hosts = self.last_scan_result.get("scan_data", {}).get("hosts", [])
        ports = []
        for h in hosts:
            ports.extend(h.get("ports", []))
        state = AgentState(
            target="",
            ports=ports,
            findings=[],
            actions_run=[self.last_scan_tool] if self.last_scan_tool else [],
        )
        return self.planner.suggest(state)

    def clarify_goal(self, goal: str) -> Dict[str, Any]:
        """
        Use the LLM to ask clarifying questions and suggest next commands.
        This does not execute tools.
        """
        goal = (goal or "").strip()
        if not goal:
            return {"questions": ["What is your target (IP/domain/URL)?"], "suggested_commands": [], "notes": "", "safety": []}

        core = {}
        try:
            if self.config_manager is not None and hasattr(self.config_manager, "config"):
                core = dict(self.config_manager.config.get("core", {}) or {})
        except Exception:
            core = {}

        payload_obj = {
            "goal": goal,
            "safety_context": {
                "allowed_hosts_configured": bool(core.get("allowed_hosts")),
                "consent_accepted": bool(core.get("consent_accepted")),
                "allow_public_ips": bool(core.get("allow_public_ips")),
            },
            "capabilities": {
                "slash_commands": ["/scan", "/audit", "/details", "/report", "/test", "/summary", "/fix", "/plan"],
                "note": "Do not run scans automatically; propose commands only.",
            },
        }

        max_chars = 12000
        try:
            if self.config_manager is not None and hasattr(self.config_manager, "config"):
                max_chars = int(self.config_manager.config.get("llm", {}).get("max_input_chars", max_chars))
        except Exception:
            pass

        content, truncated = prepare_json_payload(payload_obj, max_chars=max_chars)
        messages = [
            {"role": "system", "content": prompts.ENGAGEMENT_CLARIFIER_PROMPT},
            {"role": "user", "content": content},
        ]
        if truncated:
            messages.insert(1, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

        try:
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                result = chat_with_meta(messages)
                if isinstance(result, tuple) and len(result) == 2:
                    resp, meta = result
                    self.last_llm_meta = meta if isinstance(meta, dict) else None
                    parsed = json.loads(resp)
                else:
                    resp = self.llm.chat(messages)
                    self.last_llm_meta = None
                    parsed = json.loads(resp)
            else:
                resp = self.llm.chat(messages)
                self.last_llm_meta = None
                parsed = json.loads(resp)

            if not isinstance(parsed, dict):
                raise ValueError("clarifier output not a dict")
            self.last_clarifier = parsed
            return parsed
        except Exception as e:
            logger.error(f"LLM clarifier failed: {e}")
            fallback = {
                "questions": [
                    "What is the exact target (IP/domain/URL) and do you own it or have written authorization?",
                    "What scope is allowed (single host, CIDR, specific URLs) and what is explicitly out of scope?",
                    "What is the goal (exposure audit, vuln discovery, auth testing, container audit)?",
                    "Any constraints (stealth vs aggressive, time limit, rate limits, credentialed vs uncredentialed)?",
                ],
                "suggested_commands": [
                    "supabash config --list-allowed-hosts",
                    "supabash config --allow-host <your-scope-entry>",
                    "supabash scan <target> --scanner nmap --profile fast --yes",
                    "supabash audit <target> --output report.json --yes",
                ],
                "notes": "Freeform planning is available, but tools run only via explicit commands.",
                "safety": ["Confirm authorization and keep targets within core.allowed_hosts."],
            }
            self.last_clarifier = fallback
            self.last_llm_meta = None
            return fallback
