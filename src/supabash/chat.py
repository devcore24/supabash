import json
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    MasscanScanner,
    RustscanScanner,
)
from supabash.audit import AuditOrchestrator
from supabash.ai_audit import AIAuditOrchestrator
from supabash.llm import LLMClient
from supabash import prompts
from supabash.agent import AgentState, MethodologyPlanner
from supabash.safety import is_allowed_target, ensure_consent, is_public_ip_target
from supabash.llm_context import prepare_json_payload
from supabash.jobs import JobManager, JobStatus
from supabash.session_state import save_state as save_session_state, load_state as load_session_state

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
    jobs: JobManager = field(default_factory=JobManager)
    # Chat memory (persisted to chat_state.json)
    messages: List[Dict[str, Any]] = field(default_factory=list)
    conversation_summary: str = ""
    turns_since_summary: int = 0
    pending_action: Optional[Dict[str, Any]] = None

    def _chat_cfg(self) -> Dict[str, Any]:
        cfg = {}
        try:
            if self.config_manager is not None and hasattr(self.config_manager, "config"):
                raw = self.config_manager.config.get("chat", {})
                if isinstance(raw, dict):
                    cfg = dict(raw)
        except Exception:
            cfg = {}
        return cfg

    def _llm_enabled(self, *, default: bool = True) -> bool:
        try:
            if self.config_manager is not None and hasattr(self.config_manager, "config"):
                llm_cfg = self.config_manager.config.get("llm", {})
                if isinstance(llm_cfg, dict) and "enabled" in llm_cfg:
                    return bool(llm_cfg.get("enabled"))
        except Exception:
            pass
        return bool(default)

    def _redact_secrets_enabled(self) -> bool:
        cfg = self._chat_cfg()
        enabled = cfg.get("redact_secrets")
        return True if enabled is None else bool(enabled)

    def _redact_text(self, text: str) -> str:
        if not self._redact_secrets_enabled():
            return text
        try:
            import re
            s = text or ""
            # Common API key/token patterns
            s = re.sub(r"\bsk-[A-Za-z0-9]{16,}\b", "sk-***REDACTED***", s)
            s = re.sub(r"\bsk-ant-[A-Za-z0-9\-]{16,}\b", "sk-ant-***REDACTED***", s)
            s = re.sub(r"(?i)(authorization\s*:\s*bearer)\s+[^\s]+", r"\1 ***REDACTED***", s)
            # Key/value forms (avoid clobbering flags like --passwords FILE)
            s = re.sub(r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+", r"\1=***REDACTED***", s)
            return s
        except Exception:
            return text

    def _truncate_message(self, text: str) -> str:
        max_chars = 4000
        try:
            cfg = self._chat_cfg()
            max_chars = int(cfg.get("max_message_chars", max_chars))
        except Exception:
            max_chars = 4000
        if max_chars <= 0:
            return ""
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 14] + "...(truncated)"

    def add_message(self, role: str, content: str, *, meta: Optional[Dict[str, Any]] = None) -> None:
        role = (role or "").strip().lower() or "user"
        if role not in ("user", "assistant", "tool", "system"):
            role = "user"
        safe = self._truncate_message(self._redact_text(content or ""))
        msg = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "role": role,
            "content": safe,
        }
        if isinstance(meta, dict) and meta:
            # keep meta small + JSON-safe
            try:
                msg["meta"] = json.loads(prepare_json_payload(meta, max_chars=8000)[0])
            except Exception:
                msg["meta"] = {"note": "meta_unavailable"}
        self.messages.append(msg)
        # Keep memory bounded
        max_msgs = 80
        try:
            cfg = self._chat_cfg()
            max_msgs = int(cfg.get("history_max_messages", max_msgs))
        except Exception:
            max_msgs = 80
        if max_msgs > 0 and len(self.messages) > max_msgs:
            del self.messages[: len(self.messages) - max_msgs]

        if role == "assistant" and isinstance(meta, dict) and meta.get("source") == "llm":
            self.turns_since_summary += 1
            self._maybe_update_conversation_summary()

    def _maybe_update_conversation_summary(self) -> None:
        cfg = self._chat_cfg()
        try:
            every = int(cfg.get("summary_every_turns", 4))
        except Exception:
            every = 4
        if every <= 0:
            return
        if self.turns_since_summary < every:
            return
        if not self._llm_enabled(default=True):
            return
        try:
            keep_last = int(cfg.get("summary_keep_last_messages", 24))
        except Exception:
            keep_last = 24
        keep_last = max(0, keep_last)
        if keep_last <= 0 or len(self.messages) <= keep_last:
            self.turns_since_summary = 0
            return

        older = self.messages[: -keep_last]
        payload_obj = {
            "existing_summary": self.conversation_summary or "",
            "older_messages": older,
        }
        max_chars = 12000
        try:
            if self.config_manager is not None and hasattr(self.config_manager, "config"):
                max_chars = int(self.config_manager.config.get("llm", {}).get("max_input_chars", max_chars))
        except Exception:
            max_chars = 12000

        content, truncated = prepare_json_payload(payload_obj, max_chars=max_chars)
        messages = [
            {"role": "system", "content": prompts.CHAT_MEMORY_SUMMARIZER_PROMPT},
            {"role": "user", "content": content},
        ]
        if truncated:
            messages.insert(1, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

        try:
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                resp, _meta = chat_with_meta(messages)
            else:
                resp = self.llm.chat(messages)
            if isinstance(resp, str) and resp.strip():
                summary = self._redact_text(resp.strip())
                try:
                    max_summary = int(cfg.get("max_summary_chars", 1200))
                except Exception:
                    max_summary = 1200
                if max_summary > 0 and len(summary) > max_summary:
                    summary = summary[: max_summary - 14] + "...(truncated)"
                self.conversation_summary = summary
                # prune older messages now that they're summarized
                self.messages = self.messages[-keep_last:]
        except Exception:
            # best-effort; keep chat usable even if LLM summarization fails
            pass
        finally:
            self.turns_since_summary = 0

    def add_tool_event(self, tool: str, event: str, content: str = "", *, meta: Optional[Dict[str, Any]] = None) -> None:
        tool = (tool or "").strip() or "tool"
        event = (event or "").strip() or "event"
        prefix = f"[{event}] {tool}"
        text = prefix if not content else f"{prefix}: {content}"
        m = dict(meta or {})
        m.setdefault("tool", tool)
        m.setdefault("event", event)
        self.add_message("tool", text, meta=m)

    def _history_messages_for_llm(self, turns: int, *, exclude_latest_user: Optional[str] = None) -> List[Dict[str, str]]:
        if turns <= 0:
            return []
        hist = []
        for msg in self.messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).strip().lower()
            if role not in ("user", "assistant"):
                continue
            content = msg.get("content")
            if not isinstance(content, str) or not content.strip():
                continue
            hist.append({"role": role, "content": self._redact_text(content)})
        hist = hist[-(turns * 2) :]
        if exclude_latest_user and hist:
            try:
                last = hist[-1]
                if last.get("role") == "user" and last.get("content", "").strip() == str(exclude_latest_user).strip():
                    hist = hist[:-1]
            except Exception:
                pass
        return hist

    def _session_context_snapshot(self) -> Dict[str, Any]:
        core = {}
        try:
            if self.config_manager is not None and hasattr(self.config_manager, "config"):
                raw = self.config_manager.config.get("core", {})
                if isinstance(raw, dict):
                    core = dict(raw)
        except Exception:
            core = {}

        def audit_counts(report: Dict[str, Any]) -> Dict[str, int]:
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in (report.get("findings") or []):
                if not isinstance(f, dict):
                    continue
                sev = str(f.get("severity", "")).upper()
                if sev not in counts:
                    continue
                counts[sev] += 1
            return counts

        scan_summary: Dict[str, Any] = {}
        if isinstance(self.last_scan_result, dict) and self.last_scan_result.get("success"):
            hosts = self.last_scan_result.get("scan_data", {}).get("hosts", []) or []
            ips = []
            open_ports = []
            for h in hosts:
                if not isinstance(h, dict):
                    continue
                ip = h.get("ip")
                if isinstance(ip, str) and ip:
                    ips.append(ip)
                for p in (h.get("ports") or []):
                    if not isinstance(p, dict):
                        continue
                    port = p.get("port")
                    svc = p.get("service")
                    if port is None:
                        continue
                    open_ports.append({"port": port, "service": svc})
            scan_summary = {
                "tool": self.last_scan_tool,
                "hosts": ips[:5],
                "open_ports_sample": open_ports[:12],
                "open_ports_count": len(open_ports),
            }

        audit_summary: Dict[str, Any] = {}
        if isinstance(self.last_audit_report, dict):
            audit_summary = {
                "target": self.last_audit_report.get("target"),
                "saved_to": self.last_audit_report.get("saved_to"),
                "counts": audit_counts(self.last_audit_report),
                "tools": [
                    {
                        "tool": r.get("tool"),
                        "success": r.get("success"),
                        "skipped": r.get("skipped"),
                    }
                    for r in (self.last_audit_report.get("results") or [])
                    if isinstance(r, dict)
                ][:20],
            }

        plan = {}
        try:
            plan = self.plan_next()
        except Exception:
            plan = {}

        return {
            "safety": {
                "allowed_hosts": list(self.allowed_hosts or core.get("allowed_hosts") or []),
                "consent_accepted": bool(core.get("consent_accepted")),
                "allow_public_ips": bool(core.get("allow_public_ips")),
            },
            "last_result_kind": self.last_result_kind,
            "last_scan": scan_summary,
            "last_audit": audit_summary,
            "current_plan": plan,
            "pending_action": self.pending_action,
        }

    def _build_llm_messages(
        self,
        system_prompt: str,
        user_payload: str,
        *,
        call_type: str,
        exclude_latest_user: Optional[str] = None,
    ) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
        cfg = self._chat_cfg()
        try:
            turns = int(cfg.get("llm_history_turns", 6))
        except Exception:
            turns = 6
        turns = max(0, turns)

        ctx_obj = self._session_context_snapshot()
        ctx_str, ctx_truncated = prepare_json_payload(ctx_obj, max_chars=6000)
        ctx_note = "Session context (scope + last results + plan)."
        if ctx_truncated:
            ctx_note += " (truncated)"

        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

        if isinstance(self.conversation_summary, str) and self.conversation_summary.strip():
            messages.append(
                {
                    "role": "system",
                    "content": f"Conversation summary (memory): {self._redact_text(self.conversation_summary.strip())}",
                }
            )

        messages.append({"role": "system", "content": f"{ctx_note}\n{ctx_str}"})

        history = self._history_messages_for_llm(turns, exclude_latest_user=exclude_latest_user)
        messages.extend(history)
        messages.append({"role": "user", "content": user_payload})

        meta = {"call_type": call_type, "history_turns": turns, "context_truncated": bool(ctx_truncated)}
        return messages, meta

    def run_scan(
        self,
        target: str,
        profile: str = "fast",
        scanner_name: str = "nmap",
        allow_public: bool = False,
        cancel_event: Any = None,
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
            result = scanner.scan(target, ports=ports, arguments=args, cancel_event=cancel_event)
        elif scanner_name == "masscan":
            ports = "1-1000"
            rate = 1000
            if profile == "full":
                ports = "1-65535"
                rate = 5000
            elif profile == "stealth":
                rate = 100
            result = scanner.scan(target, ports=ports, rate=rate, arguments=args, cancel_event=cancel_event)
        else:  # rustscan
            ports = "1-1000"
            batch = 2000
            if profile == "full":
                ports = "1-65535"
                batch = 5000
            elif profile == "stealth":
                batch = 1000
            result = scanner.scan(target, ports=ports, batch=batch, arguments=args, cancel_event=cancel_event)

        self.last_scan_result = result
        self.last_scan_tool = scanner_name
        self.last_result_kind = "scan"
        return result

    def run_audit(
        self,
        target: str,
        *,
        agentic: bool = False,
        llm_plan: bool = True,
        max_actions: int = 10,
        no_llm: bool = False,
        compliance_profile: Optional[str] = None,
        container_image: Optional[str] = None,
        mode: str = "normal",
        nuclei_rate_limit: int = 0,
        gobuster_threads: int = 10,
        gobuster_wordlist: Optional[str] = None,
        parallel_web: bool = False,
        max_workers: int = 3,
        run_nikto: bool = False,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        allow_public: bool = False,
        output: Optional[Path] = None,
        markdown: Optional[Path] = None,
        cancel_event: Any = None,
        progress_cb: Any = None,
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

        orchestrator = (
            self.audit_orchestrator_factory()
            if callable(self.audit_orchestrator_factory)
            else (AIAuditOrchestrator() if agentic else AuditOrchestrator())
        )
        run_kwargs = {
            "container_image": container_image,
            "mode": mode,
            "compliance_profile": compliance_profile,
            "nuclei_rate_limit": nuclei_rate_limit,
            "gobuster_threads": gobuster_threads,
            "gobuster_wordlist": gobuster_wordlist,
            "parallel_web": parallel_web,
            "max_workers": max_workers,
            "run_nikto": run_nikto,
            "remediate": remediate,
            "max_remediations": max_remediations,
            "min_remediation_severity": min_remediation_severity,
            "cancel_event": cancel_event,
            "progress_cb": progress_cb,
            "use_llm": not bool(no_llm),
        }
        if agentic:
            run_kwargs["llm_plan"] = bool(llm_plan)
            run_kwargs["max_actions"] = int(max_actions)

        report = orchestrator.run(
            target,
            output,
            **run_kwargs,
        )
        self.last_audit_report = report
        self.last_result_kind = "audit"

        md_target = markdown
        if md_target is None and output is not None:
            md_target = output.with_suffix(".md")

        if md_target is not None and report.get("saved_to"):
            try:
                from supabash.report import write_markdown
                from supabash.report_export import export_from_markdown_file
                md_path = write_markdown(report, md_target)
                report.setdefault("_chat", {})["markdown_saved_to"] = md_path
                exports = export_from_markdown_file(Path(md_path), config=(self.config_manager.config if self.config_manager is not None else None))
                if exports.html_path:
                    report.setdefault("_chat", {})["html_saved_to"] = str(exports.html_path)
                if exports.pdf_path:
                    report.setdefault("_chat", {})["pdf_saved_to"] = str(exports.pdf_path)
                if exports.html_error:
                    report.setdefault("_chat", {})["html_export_error"] = exports.html_error
                if exports.pdf_error:
                    report.setdefault("_chat", {})["pdf_export_error"] = exports.pdf_error
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

    def start_audit_job(
        self,
        target: str,
        *,
        agentic: bool = False,
        llm_plan: bool = True,
        max_actions: int = 10,
        no_llm: bool = False,
        compliance_profile: Optional[str] = None,
        container_image: Optional[str] = None,
        mode: str = "normal",
        nuclei_rate_limit: int = 0,
        gobuster_threads: int = 10,
        gobuster_wordlist: Optional[str] = None,
        parallel_web: bool = False,
        max_workers: int = 3,
        run_nikto: bool = False,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        allow_public: bool = False,
        output: Optional[Path] = None,
        markdown: Optional[Path] = None,
    ):
        job_ref = {"job": None}

        def progress_cb(event: str, tool: str, message: str, agg: Dict[str, Any]):
            job = job_ref.get("job")
            if not job:
                return
            step = f"{event}:{tool}".strip(":")
            job.status.current_step = step
            job.status.message = message or step
            try:
                line = f"{event} {tool}".strip()
                if message:
                    line = f"{line}: {message}"
                job.status.events.append(line)
                if len(job.status.events) > 25:
                    del job.status.events[: len(job.status.events) - 25]
            except Exception:
                pass

        def fn():
            job = job_ref.get("job")
            cancel_event = job.cancel_event if job else None
            return self.run_audit(
                target,
                agentic=agentic,
                llm_plan=llm_plan,
                max_actions=max_actions,
                no_llm=no_llm,
                compliance_profile=compliance_profile,
                container_image=container_image,
                mode=mode,
                nuclei_rate_limit=nuclei_rate_limit,
                gobuster_threads=gobuster_threads,
                gobuster_wordlist=gobuster_wordlist,
                parallel_web=parallel_web,
                max_workers=max_workers,
                run_nikto=run_nikto,
                remediate=remediate,
                max_remediations=max_remediations,
                min_remediation_severity=min_remediation_severity,
                allow_public=allow_public,
                output=output,
                markdown=markdown,
                cancel_event=cancel_event,
                progress_cb=progress_cb,
            )

        job = self.jobs.start_job("audit", target, fn)
        job_ref["job"] = job
        job.status.message = "Audit started"
        try:
            job.status.events.append("start: audit started")
        except Exception:
            pass
        return job

    def start_scan_job(self, target: str, profile: str = "fast", scanner_name: str = "nmap", allow_public: bool = False):
        job_ref = {"job": None}
        def fn():
            job = job_ref.get("job")
            cancel_event = job.cancel_event if job else None
            if cancel_event is not None and cancel_event.is_set():
                return {"success": False, "error": "Canceled before start", "canceled": True}
            return self.run_scan(target, profile=profile, scanner_name=scanner_name, allow_public=allow_public, cancel_event=cancel_event)

        job = self.jobs.start_job("scan", target, fn)
        job_ref["job"] = job
        job.status.message = "Scan started"
        try:
            job.status.events.append("start: scan started")
        except Exception:
            pass
        return job

    def job_status(self) -> Optional[JobStatus]:
        return self.jobs.get_status()

    def stop_job(self) -> bool:
        return self.jobs.cancel_active()

    def finalize_job_if_done(self) -> Optional[Dict[str, Any]]:
        return self.jobs.take_result_if_done()

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

    def export_state(self) -> Dict[str, Any]:
        return {
            "schema_version": 2,
            "last_result_kind": self.last_result_kind,
            "last_scan_tool": self.last_scan_tool,
            "last_scan_result": self.last_scan_result,
            "last_audit_report": self.last_audit_report,
            "last_llm_meta": self.last_llm_meta,
            "last_clarifier": self.last_clarifier,
            "messages": self.messages,
            "conversation_summary": self.conversation_summary,
            "turns_since_summary": self.turns_since_summary,
            "pending_action": self.pending_action,
        }

    def import_state(self, state: Dict[str, Any]) -> bool:
        if not isinstance(state, dict):
            return False
        schema_version = state.get("schema_version")
        self.last_result_kind = state.get("last_result_kind") if isinstance(state.get("last_result_kind"), str) else None
        self.last_scan_tool = state.get("last_scan_tool") if isinstance(state.get("last_scan_tool"), str) else None
        self.last_scan_result = state.get("last_scan_result") if isinstance(state.get("last_scan_result"), dict) else None
        self.last_audit_report = state.get("last_audit_report") if isinstance(state.get("last_audit_report"), dict) else None
        self.last_llm_meta = state.get("last_llm_meta") if isinstance(state.get("last_llm_meta"), dict) else None
        self.last_clarifier = state.get("last_clarifier") if isinstance(state.get("last_clarifier"), dict) else None
        if schema_version == 2:
            msgs = state.get("messages")
            self.messages = msgs if isinstance(msgs, list) else []
            self.conversation_summary = state.get("conversation_summary") if isinstance(state.get("conversation_summary"), str) else ""
            try:
                self.turns_since_summary = int(state.get("turns_since_summary", 0))
            except Exception:
                self.turns_since_summary = 0
            pending = state.get("pending_action")
            self.pending_action = pending if isinstance(pending, dict) else None
        else:
            # Back-compat: older state files had no chat memory.
            self.messages = []
            self.conversation_summary = ""
            self.turns_since_summary = 0
            self.pending_action = None
        return True

    def save_state(self, path: Path) -> Dict[str, Any]:
        ok, truncated = save_session_state(path, self.export_state())
        return {"success": ok, "truncated": truncated, "path": str(path)}

    def load_state(self, path: Path) -> Dict[str, Any]:
        state = load_session_state(path)
        if not state:
            return {"success": False, "path": str(path)}
        return {"success": self.import_state(state), "path": str(path)}

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
        return sys.executable or "python3"

    def summarize_findings(self) -> Optional[str]:
        if not self.last_scan_result:
            return None
        if not self._llm_enabled(default=True):
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
            messages, extra = self._build_llm_messages(
                prompts.ANALYZER_PROMPT,
                content,
                call_type="summary",
            )
            if truncated:
                messages.insert(2, {"role": "system", "content": "Note: Tool output was truncated to fit context limits."})
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
                        meta.update(extra)
                        ctx_usage = getattr(self.llm, "context_window_usage", None)
                        if callable(ctx_usage):
                            usage_info = ctx_usage(messages)
                            if isinstance(usage_info, dict):
                                meta.update(usage_info)
                    self.last_llm_meta = meta
                    return resp
            self.last_llm_meta = None
            return self.llm.chat(messages)
        except Exception as e:
            logger.error(f"LLM summary failed: {e}")
            return None

    def remediate(self, title: str, evidence: str = "", severity: str = "") -> Optional[str]:
        try:
            if not self._llm_enabled(default=True):
                return None
            finding = {"title": title, "evidence": evidence, "severity": severity}
            max_chars = 12000
            try:
                cfg = self.config_manager
                if cfg is not None and hasattr(cfg, "config"):
                    max_chars = int(cfg.config.get("llm", {}).get("max_input_chars", max_chars))
            except Exception:
                pass
            content, truncated = prepare_json_payload(finding, max_chars=max_chars)
            messages, extra = self._build_llm_messages(
                prompts.REMEDIATOR_PROMPT,
                content,
                call_type="remediate",
            )
            if truncated:
                messages.insert(2, {"role": "system", "content": "Note: Input was truncated to fit context limits."})
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
                        meta.update(extra)
                        ctx_usage = getattr(self.llm, "context_window_usage", None)
                        if callable(ctx_usage):
                            usage_info = ctx_usage(messages)
                            if isinstance(usage_info, dict):
                                meta.update(usage_info)
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
        if not self._llm_enabled(default=True):
            self.last_llm_meta = None
            fallback = {
                "questions": [
                    "What is the exact target (IP/domain/URL) and do you own it or have written authorization?",
                    "What scope is allowed (single host, CIDR, specific URLs) and what is explicitly out of scope?",
                    "What is the goal (exposure audit, vuln discovery, auth testing, container audit)?",
                    "Any constraints (stealth vs aggressive, time limit, rate limits, credentialed vs uncredentialed)?",
                ],
                "suggested_commands": [
                    "/scan <target> --scanner nmap --profile fast",
                    "/audit <target> --mode normal",
                ],
                "notes": "LLM is disabled (offline mode). Use slash commands to run tools.",
                "safety": ["Confirm authorization and keep targets within core.allowed_hosts."],
            }
            self.last_clarifier = fallback
            return fallback

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
        messages, extra = self._build_llm_messages(
            prompts.ENGAGEMENT_CLARIFIER_PROMPT,
            content,
            call_type="clarify_goal",
            exclude_latest_user=goal,
        )
        if truncated:
            messages.insert(2, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

        try:
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                result = chat_with_meta(messages)
                if isinstance(result, tuple) and len(result) == 2:
                    resp, meta = result
                    if isinstance(meta, dict):
                        meta = dict(meta)
                        meta.update(extra)
                        ctx_usage = getattr(self.llm, "context_window_usage", None)
                        if callable(ctx_usage):
                            usage_info = ctx_usage(messages)
                            if isinstance(usage_info, dict):
                                meta.update(usage_info)
                        self.last_llm_meta = meta
                    else:
                        self.last_llm_meta = None
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
                    "/scan <target> --scanner nmap --profile fast",
                    "/audit <target> --mode normal",
                ],
                "notes": "Freeform planning is available, but tools run only via explicit commands.",
                "safety": ["Confirm authorization and keep targets within core.allowed_hosts."],
            }
            self.last_clarifier = fallback
            self.last_llm_meta = None
            return fallback
