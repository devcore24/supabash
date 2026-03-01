from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from threading import Event
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from supabash.audit import AuditOrchestrator
from supabash.agent import MethodologyPlanner
from supabash import prompts
from supabash.llm import ToolCallingNotSupported, ToolCallingError
from supabash.llm_context import prepare_json_payload
from supabash.report_order import stable_sort_results
from supabash.report import (
    build_compliance_coverage_matrix,
    build_recommended_next_actions,
    normalize_report_summary,
)
from supabash.report_schema import annotate_schema_validation


class AIAuditOrchestrator(AuditOrchestrator):
    """
    Combined "agentic audit":
      1) Run the deterministic baseline audit pipeline (no LLM)
      2) Optionally run a bounded, tool-calling agentic expansion phase
      3) Summarize + remediate on the combined results and write one report
    """

    def __init__(
        self,
        scanners: Optional[Dict[str, Any]] = None,
        llm_client: Optional[Any] = None,
        planner: Optional[MethodologyPlanner] = None,
    ):
        super().__init__(scanners=scanners, llm_client=llm_client)
        self.planner = planner or MethodologyPlanner()

    def _write_replay_trace(self, agg: Dict[str, Any], output: Optional[Path]) -> Optional[Dict[str, Any]]:
        if output is None:
            return None
        try:
            report_root = output.parent
            replay_path = report_root / f"{output.stem}-replay.json"
            replay_md_path = report_root / f"{output.stem}-replay.md"
            ai = agg.get("ai_audit")
            decision_trace = ai.get("decision_trace") if isinstance(ai, dict) else []
            if not isinstance(decision_trace, list):
                decision_trace = []
            actions = ai.get("actions") if isinstance(ai, dict) else []
            if not isinstance(actions, list):
                actions = []
            planner_context_history = ai.get("planner_context_history") if isinstance(ai, dict) else []
            if not isinstance(planner_context_history, list):
                planner_context_history = []
            commands = [
                {"tool": r.get("tool"), "command": r.get("command"), "target": r.get("target"), "phase": r.get("phase")}
                for r in (agg.get("results", []) or [])
                if isinstance(r, dict) and isinstance(r.get("command"), str) and str(r.get("command")).strip()
            ]
            generated_at = time.time()
            payload = {
                "version": 1,
                "generated_at": generated_at,
                "generated_at_utc": self._fmt_unix_utc(generated_at),
                "report_file": str(output.name),
                "report_kind": agg.get("report_kind"),
                "target": agg.get("target"),
                "scan_host": agg.get("scan_host"),
                "compliance_profile": agg.get("compliance_profile"),
                "compliance_framework": agg.get("compliance_framework"),
                "planner_type": ai.get("planner", {}).get("type") if isinstance(ai, dict) else None,
                "planner_mode": ai.get("planner_mode") if isinstance(ai, dict) else None,
                "max_actions": ai.get("max_actions") if isinstance(ai, dict) else None,
                "actions": actions,
                "decision_trace": decision_trace,
                "commands": commands,
            }
            replay_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            def _fmt_ts(ts: Any) -> str:
                try:
                    if ts is None:
                        return ""
                    return self._fmt_unix_utc(float(ts))
                except Exception:
                    return ""

            def _short(value: Any, limit: int = 220) -> str:
                text = str(value or "").strip()
                if len(text) <= limit:
                    return text
                return text[: limit - 3].rstrip() + "..."

            md_lines: List[str] = []
            md_lines.append("# Audit Replay Trace")
            md_lines.append("")
            md_lines.append(
                "This replay summarizes the recorded action sequence and command execution so a reviewer can understand the run flow quickly."
            )
            md_lines.append("")
            md_lines.append("## Metadata")
            md_lines.append(f"- report_file: `{output.name}`")
            md_lines.append(f"- generated_at: {_fmt_ts(generated_at)}")
            if isinstance(agg.get("compliance_framework"), str) and str(agg.get("compliance_framework")).strip():
                md_lines.append(f"- compliance_framework: {str(agg.get('compliance_framework')).strip()}")
            elif isinstance(agg.get("compliance_profile"), str) and str(agg.get("compliance_profile")).strip():
                md_lines.append(f"- compliance_profile: {str(agg.get('compliance_profile')).strip()}")
            md_lines.append(f"- decision_steps: {len(decision_trace)}")
            md_lines.append(f"- action_records: {len(actions)}")
            md_lines.append(f"- command_records: {len(commands)}")

            if decision_trace:
                md_lines.append("\n## Decision Steps")
                for step in decision_trace[:80]:
                    if not isinstance(step, dict):
                        continue
                    step_no = step.get("iteration")
                    started = _fmt_ts(step.get("started_at")) or "-"
                    finished = _fmt_ts(step.get("finished_at")) or "-"
                    decision = step.get("decision") if isinstance(step.get("decision"), dict) else {}
                    d_result = _short(decision.get("result"), 60) or "unknown"
                    d_reason = _short(decision.get("reason"), 180)
                    line = f"- Step {step_no}: {d_result}"
                    if d_reason:
                        line = f"{line} ({d_reason})"
                    line = f"{line} start={started} end={finished}"
                    md_lines.append(line)

                    planner = step.get("planner") if isinstance(step.get("planner"), dict) else {}
                    if planner:
                        candidate_count = planner.get("candidate_count")
                        notes = _short(planner.get("notes"), 220)
                        md_lines.append(f"  - Planner candidates: {candidate_count}")
                        if notes:
                            md_lines.append(f"  - Planner notes: {notes}")
                    replan = step.get("replan") if isinstance(step.get("replan"), dict) else {}
                    if replan:
                        attempted = bool(replan.get("attempted"))
                        reason = _short(replan.get("reason"), 160)
                        excluded = replan.get("excluded_count")
                        md_lines.append(
                            f"  - Replan: attempted={str(attempted).lower()} reason={reason or '-'} excluded={excluded}"
                        )
                    selected = step.get("selected_action") if isinstance(step.get("selected_action"), dict) else {}
                    if selected:
                        tool = _short(selected.get("tool"), 40) or "-"
                        target = _short(selected.get("target"), 120)
                        priority = selected.get("priority")
                        sel_line = f"tool={tool}"
                        if target:
                            sel_line = f"{sel_line} target={target}"
                        if priority is not None:
                            sel_line = f"{sel_line} priority={priority}"
                        md_lines.append(f"  - Selected: {sel_line}")
                    outcome = step.get("outcome") if isinstance(step.get("outcome"), dict) else {}
                    if outcome:
                        status = _short(outcome.get("status"), 40)
                        delta = outcome.get("findings_count_delta")
                        web_delta = outcome.get("web_target_count_delta")
                        out_line = f"status={status or '-'}"
                        if isinstance(delta, int):
                            out_line = f"{out_line} findings_delta={delta}"
                        if isinstance(web_delta, int):
                            out_line = f"{out_line} web_targets_delta={web_delta}"
                        md_lines.append(f"  - Outcome: {out_line}")

            if actions:
                md_lines.append("\n## Executed Actions")
                for idx, action in enumerate(actions[:120], start=1):
                    if not isinstance(action, dict):
                        continue
                    tool = _short(action.get("tool"), 40) or "-"
                    target = _short(action.get("target"), 120)
                    profile = _short(action.get("profile"), 60)
                    status = "skipped" if action.get("skipped") else ("success" if action.get("success") else "failed")
                    line = f"- {idx}. {tool} status={status}"
                    if target:
                        line = f"{line} target={target}"
                    if profile:
                        line = f"{line} profile={profile}"
                    md_lines.append(line)
                    reason = _short(action.get("reason"), 220)
                    if reason:
                        md_lines.append(f"  - reason: {reason}")

            if commands:
                md_lines.append("\n## Commands")
                for idx, cmd in enumerate(commands[:200], start=1):
                    if not isinstance(cmd, dict):
                        continue
                    tool = _short(cmd.get("tool"), 40) or "-"
                    phase = _short(cmd.get("phase"), 40)
                    target = _short(cmd.get("target"), 120)
                    command = _short(cmd.get("command"), 260) or "-"
                    line = f"- {idx}. {tool}"
                    if phase:
                        line = f"{line} phase={phase}"
                    if target:
                        line = f"{line} target={target}"
                    md_lines.append(line)
                    md_lines.append(f"  - command: `{command}`")

            replay_md_path.write_text("\n".join(md_lines).rstrip() + "\n", encoding="utf-8")

            rel = str(replay_path.relative_to(report_root))
            rel_md = str(replay_md_path.relative_to(report_root))
            return {"file": rel, "markdown_file": rel_md, "step_count": len(decision_trace), "version": 1}
        except Exception as e:
            agg["replay_trace_error"] = str(e)
            return None

    def _write_llm_reasoning_trace(self, agg: Dict[str, Any], output: Optional[Path]) -> Optional[Dict[str, Any]]:
        if output is None:
            return None
        try:
            report_root = output.parent
            trace_json_path = report_root / f"{output.stem}-llm-trace.json"
            trace_md_path = report_root / f"{output.stem}-llm-trace.md"

            ai = agg.get("ai_audit")
            decision_trace = ai.get("decision_trace") if isinstance(ai, dict) else []
            if not isinstance(decision_trace, list):
                decision_trace = []
            actions = ai.get("actions") if isinstance(ai, dict) else []
            if not isinstance(actions, list):
                actions = []
            planner_context_history = ai.get("planner_context_history") if isinstance(ai, dict) else []
            if not isinstance(planner_context_history, list):
                planner_context_history = []

            llm_obj = agg.get("llm")
            llm_calls = llm_obj.get("calls") if isinstance(llm_obj, dict) else []
            if not isinstance(llm_calls, list):
                llm_calls = []
            planner_calls = [c for c in llm_calls if isinstance(c, dict) and str(c.get("call_type") or "").strip().lower() == "plan"]
            summary_calls = [c for c in llm_calls if isinstance(c, dict) and str(c.get("call_type") or "").strip().lower() == "summary"]

            thinking_events = agg.get("llm_thinking_events")
            if not isinstance(thinking_events, list):
                thinking_events = []

            if not thinking_events and not decision_trace and not llm_calls:
                return None

            generated_at = time.time()
            payload = {
                "version": 1,
                "generated_at": generated_at,
                "generated_at_utc": self._fmt_unix_utc(generated_at),
                "report_file": str(output.name),
                "report_kind": agg.get("report_kind"),
                "target": agg.get("target"),
                "scan_host": agg.get("scan_host"),
                "compliance_profile": agg.get("compliance_profile"),
                "compliance_framework": agg.get("compliance_framework"),
                "note": (
                    "This trace includes explicit planner rationale/messages and tool-selection decisions. "
                    "It does not include hidden model internals."
                ),
                "llm_events": thinking_events,
                "llm_calls": llm_calls,
                "planner_calls": planner_calls,
                "summary_calls": summary_calls,
                "planner_context_history": planner_context_history,
                "decision_trace": decision_trace,
                "actions": actions,
            }
            trace_json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            def _fmt_ts(ts: Any) -> str:
                try:
                    if ts is None:
                        return ""
                    return self._fmt_unix_utc(float(ts))
                except Exception:
                    return ""

            def _short(value: Any, limit: int = 220) -> str:
                text = str(value or "").strip()
                if len(text) <= limit:
                    return text
                return text[: limit - 3].rstrip() + "..."

            md_lines: List[str] = []
            md_lines.append("# LLM Reasoning Trace")
            md_lines.append("")
            md_lines.append(
                "This trace captures explicit planner rationale/messages and decision points recorded during execution. "
                "It does not include hidden model internals."
            )
            md_lines.append("")
            md_lines.append("## Metadata")
            md_lines.append(f"- report_file: `{output.name}`")
            if isinstance(agg.get("compliance_framework"), str) and str(agg.get("compliance_framework")).strip():
                md_lines.append(f"- compliance_framework: {str(agg.get('compliance_framework')).strip()}")
            elif isinstance(agg.get("compliance_profile"), str) and str(agg.get("compliance_profile")).strip():
                md_lines.append(f"- compliance_profile: {str(agg.get('compliance_profile')).strip()}")
            md_lines.append(f"- generated_at: {_fmt_ts(generated_at)}")
            md_lines.append(f"- llm_event_count: {len(thinking_events)}")
            md_lines.append(f"- decision_steps: {len(decision_trace)}")
            md_lines.append(f"- llm_calls: {len(llm_calls)}")
            md_lines.append(f"- planner_calls: {len(planner_calls)}")
            md_lines.append(f"- summary_calls: {len(summary_calls)}")
            md_lines.append(f"- planner_context_snapshots: {len(planner_context_history)}")

            if planner_context_history:
                md_lines.append("\n## Planner Context Snapshots")
                for idx, item in enumerate(planner_context_history[:120], start=1):
                    if not isinstance(item, dict):
                        continue
                    when = _fmt_ts(item.get("timestamp")) or "-"
                    remaining = item.get("remaining_actions")
                    findings_total = item.get("findings_total")
                    clusters = item.get("finding_cluster_count")
                    open_high = item.get("open_high_risk_cluster_count")
                    md_lines.append(
                        f"- {idx}. [{when}] remaining={remaining} findings={findings_total} "
                        f"clusters={clusters} open_high_risk={open_high}"
                    )
                    last_action = item.get("last_action")
                    if isinstance(last_action, dict):
                        tool = _short(last_action.get("tool"), 40) or "-"
                        target = _short(last_action.get("target"), 120) or "-"
                        status = _short(last_action.get("status"), 40) or "-"
                        gain = last_action.get("gain_score")
                        md_lines.append(f"  - last_action: tool={tool} target={target} status={status} gain={gain}")

            if thinking_events:
                md_lines.append("\n## Event Stream")
                for idx, event in enumerate(thinking_events[:200], start=1):
                    if not isinstance(event, dict):
                        continue
                    when = _fmt_ts(event.get("timestamp")) or "-"
                    etype = _short(event.get("event"), 60) or "llm_event"
                    tool = _short(event.get("tool"), 60) or "-"
                    msg = _short(event.get("message"), 300) or "-"
                    md_lines.append(f"- {idx}. [{when}] {etype} tool={tool} :: {msg}")

            if decision_trace:
                md_lines.append("\n## Decision Steps")
                for step in decision_trace[:60]:
                    if not isinstance(step, dict):
                        continue
                    step_no = step.get("iteration")
                    started = _fmt_ts(step.get("started_at")) or "-"
                    finished = _fmt_ts(step.get("finished_at")) or "-"
                    decision = step.get("decision") if isinstance(step.get("decision"), dict) else {}
                    decision_result = _short(decision.get("result"), 60) or "unknown"
                    decision_reason = _short(decision.get("reason"), 160)
                    line = f"- Step {step_no}: {decision_result}"
                    if decision_reason:
                        line = f"{line} ({decision_reason})"
                    line = f"{line} start={started} end={finished}"
                    md_lines.append(line)

                    planner = step.get("planner") if isinstance(step.get("planner"), dict) else {}
                    if planner:
                        cand_count = planner.get("candidate_count")
                        notes = _short(planner.get("notes"), 200)
                        stop_flag = bool(planner.get("stop"))
                        md_lines.append(f"  - Planner: candidates={cand_count} stop={str(stop_flag).lower()}")
                        if notes:
                            md_lines.append(f"  - Planner notes: {notes}")
                        candidates = planner.get("candidates")
                        if isinstance(candidates, list) and candidates:
                            top = candidates[0] if isinstance(candidates[0], dict) else {}
                            if isinstance(top, dict):
                                tool = _short(top.get("tool"), 40)
                                target = _short(top.get("target"), 120)
                                priority = top.get("priority")
                                md_lines.append(f"  - Top candidate: tool={tool} target={target} priority={priority}")

                    replan = step.get("replan") if isinstance(step.get("replan"), dict) else {}
                    if replan:
                        attempted = bool(replan.get("attempted"))
                        reason = _short(replan.get("reason"), 180)
                        excluded_count = replan.get("excluded_count")
                        md_lines.append(
                            f"  - Replan: attempted={str(attempted).lower()} reason={reason or '-'} excluded={excluded_count}"
                        )

                    replans = step.get("planner_replans")
                    if isinstance(replans, list) and replans:
                        first = replans[0] if isinstance(replans[0], dict) else {}
                        if isinstance(first, dict):
                            cand_count = first.get("candidate_count")
                            notes = _short(first.get("notes"), 180)
                            md_lines.append(f"  - Replan planner: candidates={cand_count}")
                            if notes:
                                md_lines.append(f"  - Replan notes: {notes}")

                    selected = step.get("selected_action") if isinstance(step.get("selected_action"), dict) else {}
                    if selected:
                        tool = _short(selected.get("tool"), 40)
                        target = _short(selected.get("target"), 120)
                        priority = selected.get("priority")
                        md_lines.append(f"  - Selected action: tool={tool} target={target} priority={priority}")

                    critique = step.get("critique") if isinstance(step.get("critique"), dict) else {}
                    if critique:
                        signal = _short(critique.get("signal"), 40)
                        summary = _short(critique.get("summary"), 240)
                        md_lines.append(f"  - Critique: signal={signal} summary={summary}")

            if llm_calls:
                md_lines.append("\n## LLM Calls")
                for idx, call in enumerate(llm_calls[:100], start=1):
                    if not isinstance(call, dict):
                        continue
                    provider = _short(call.get("provider"), 40) or "-"
                    model = _short(call.get("model"), 80) or "-"
                    call_type = _short(call.get("call_type"), 40) or "unknown"
                    stage = _short(call.get("stage"), 80)
                    usage = call.get("usage") if isinstance(call.get("usage"), dict) else {}
                    total_tokens = usage.get("total_tokens")
                    cost = call.get("cost_usd")
                    parts = [f"{idx}. type={call_type}", f"provider={provider}", f"model={model}"]
                    if stage:
                        parts.append(f"stage={stage}")
                    if isinstance(total_tokens, (int, float)):
                        parts.append(f"tokens={int(total_tokens)}")
                    if isinstance(cost, (int, float)):
                        parts.append(f"cost_usd={float(cost):.6f}")
                    md_lines.append(f"- {' | '.join(parts)}")

            trace_md_path.write_text("\n".join(md_lines).rstrip() + "\n", encoding="utf-8")

            return {
                "version": 1,
                "json_file": str(trace_json_path.relative_to(report_root)),
                "markdown_file": str(trace_md_path.relative_to(report_root)),
                "event_count": len(thinking_events),
                "decision_steps": len(decision_trace),
                "llm_calls": len(llm_calls),
            }
        except Exception as e:
            agg["llm_reasoning_trace_error"] = str(e)
            return None

    def run(
        self,
        target: str,
        output: Optional[Path],
        *,
        container_image: Optional[str] = None,
        mode: str = "normal",
        compliance_profile: Optional[str] = None,
        nuclei_rate_limit: int = 0,
        nuclei_tags: Optional[str] = None,
        nuclei_severity: Optional[str] = None,
        nuclei_templates: Optional[str] = None,
        gobuster_threads: int = 10,
        gobuster_wordlist: Optional[str] = None,
        parallel_web: bool = False,
        max_workers: int = 3,
        run_nikto: bool = False,
        run_browser_use: bool = True,
        run_hydra: bool = False,
        hydra_usernames: Optional[str] = None,
        hydra_passwords: Optional[str] = None,
        hydra_services: Optional[str] = None,
        hydra_threads: int = 4,
        hydra_options: Optional[str] = None,
        run_theharvester: bool = False,
        theharvester_sources: Optional[str] = None,
        theharvester_limit: Optional[int] = None,
        theharvester_start: Optional[int] = None,
        theharvester_args: Optional[str] = None,
        run_netdiscover: bool = False,
        netdiscover_range: Optional[str] = None,
        netdiscover_interface: Optional[str] = None,
        netdiscover_passive: bool = False,
        netdiscover_fast: bool = True,
        netdiscover_args: Optional[str] = None,
        run_aircrack: bool = False,
        aircrack_interface: Optional[str] = None,
        aircrack_channel: Optional[str] = None,
        aircrack_args: Optional[str] = None,
        aircrack_airmon: bool = False,
        run_medusa: bool = False,
        medusa_usernames: Optional[str] = None,
        medusa_passwords: Optional[str] = None,
        medusa_module: Optional[str] = None,
        medusa_port: Optional[int] = None,
        medusa_threads: int = 4,
        medusa_timeout: int = 10,
        medusa_options: Optional[str] = None,
        run_crackmapexec: bool = False,
        cme_protocol: str = "smb",
        cme_username: Optional[str] = None,
        cme_password: Optional[str] = None,
        cme_domain: Optional[str] = None,
        cme_hashes: Optional[str] = None,
        cme_module: Optional[str] = None,
        cme_module_options: Optional[str] = None,
        cme_enum: Optional[str] = None,
        cme_args: Optional[str] = None,
        run_scoutsuite: bool = False,
        scoutsuite_provider: str = "aws",
        scoutsuite_args: Optional[str] = None,
        run_prowler: bool = False,
        prowler_args: Optional[str] = None,
        llm_plan: bool = True,
        max_actions: int = 10,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        cancel_event: Optional[Event] = None,
        progress_cb: Optional[Any] = None,
        use_llm: bool = True,
    ) -> Dict[str, Any]:
        run_error: Optional[str] = None
        normalized = self._normalize_target(target)
        normalized_compliance = self._normalize_compliance_profile(compliance_profile)
        compliance_label = self._compliance_profile_label(normalized_compliance)
        compliance_focus = None
        if normalized_compliance:
            profile_spec = self._compliance_profiles().get(normalized_compliance, {})
            if isinstance(profile_spec, dict):
                compliance_focus = profile_spec.get("focus")

        def canceled() -> bool:
            return bool(cancel_event and cancel_event.is_set())

        def note(event: str, tool: str = "", message: str = "", agg: Optional[Dict[str, Any]] = None) -> None:
            if isinstance(agg, dict) and isinstance(event, str) and event.startswith("llm_"):
                try:
                    events = agg.setdefault("llm_thinking_events", [])
                    if isinstance(events, list):
                        events.append(
                            {
                                "timestamp": time.time(),
                                "event": str(event),
                                "tool": str(tool or ""),
                                "message": str(message or ""),
                            }
                        )
                except Exception:
                    pass
            if callable(progress_cb):
                try:
                    progress_cb(event=event, tool=tool, message=message, agg=agg or {})
                except Exception:
                    pass

        # Phase 1: Baseline (deterministic) audit pipeline
        note("phase_start", "baseline", "Running baseline audit pipeline")
        baseline = super().run(
            target,
            None,
            container_image=container_image,
            mode=mode,
            compliance_profile=normalized_compliance,
            nuclei_rate_limit=nuclei_rate_limit,
            nuclei_tags=nuclei_tags,
            nuclei_severity=nuclei_severity,
            nuclei_templates=nuclei_templates,
            gobuster_threads=gobuster_threads,
            gobuster_wordlist=gobuster_wordlist,
            run_nikto=run_nikto,
            run_browser_use=run_browser_use,
            run_hydra=run_hydra,
            hydra_usernames=hydra_usernames,
            hydra_passwords=hydra_passwords,
            hydra_services=hydra_services,
            hydra_threads=hydra_threads,
            hydra_options=hydra_options,
            run_theharvester=run_theharvester,
            theharvester_sources=theharvester_sources,
            theharvester_limit=theharvester_limit,
            theharvester_start=theharvester_start,
            theharvester_args=theharvester_args,
            run_netdiscover=run_netdiscover,
            netdiscover_range=netdiscover_range,
            netdiscover_interface=netdiscover_interface,
            netdiscover_passive=netdiscover_passive,
            netdiscover_fast=netdiscover_fast,
            netdiscover_args=netdiscover_args,
            run_aircrack=run_aircrack,
            aircrack_interface=aircrack_interface,
            aircrack_channel=aircrack_channel,
            aircrack_args=aircrack_args,
            aircrack_airmon=aircrack_airmon,
            run_medusa=run_medusa,
            medusa_usernames=medusa_usernames,
            medusa_passwords=medusa_passwords,
            medusa_module=medusa_module,
            medusa_port=medusa_port,
            medusa_threads=medusa_threads,
            medusa_timeout=medusa_timeout,
            medusa_options=medusa_options,
            run_crackmapexec=run_crackmapexec,
            cme_protocol=cme_protocol,
            cme_username=cme_username,
            cme_password=cme_password,
            cme_domain=cme_domain,
            cme_hashes=cme_hashes,
            cme_module=cme_module,
            cme_module_options=cme_module_options,
            cme_enum=cme_enum,
            cme_args=cme_args,
            run_scoutsuite=run_scoutsuite,
            scoutsuite_provider=scoutsuite_provider,
            scoutsuite_args=scoutsuite_args,
            run_prowler=run_prowler,
            prowler_args=prowler_args,
            remediate=False,
            max_remediations=max_remediations,
            min_remediation_severity=min_remediation_severity,
            cancel_event=cancel_event,
            progress_cb=progress_cb,
            parallel_web=parallel_web,
            max_workers=max_workers,
            use_llm=False,
        )
        note("phase_end", "baseline", "Baseline audit finished", agg=baseline)

        # If baseline was canceled, return early (best-effort).
        if canceled() or baseline.get("canceled"):
            baseline["report_kind"] = "ai_audit"
            baseline.setdefault("ai_audit", {})["canceled"] = True
            baseline.setdefault("ai_audit", {})["phase"] = "baseline"
            baseline["finished_at"] = time.time()
            try:
                annotate_schema_validation(baseline, kind="audit")
            except Exception:
                pass
            if output is not None:
                self._write_evidence_pack(baseline, output)
                replay_meta = self._write_replay_trace(baseline, output)
                if isinstance(replay_meta, dict):
                    baseline["replay_trace"] = replay_meta
                llm_trace_meta = self._write_llm_reasoning_trace(baseline, output)
                if isinstance(llm_trace_meta, dict):
                    baseline["llm_reasoning_trace"] = llm_trace_meta
                try:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
                    baseline["saved_to"] = str(output)
                except Exception as e:
                    baseline["saved_to"] = None
                    baseline["write_error"] = str(e)
            else:
                baseline["saved_to"] = None
            return baseline

        # Start building the unified report (reuse baseline structure, recompute findings/summary later).
        agg: Dict[str, Any] = baseline
        baseline_finished_at = agg.get("finished_at")
        agg["report_kind"] = "ai_audit"
        ai_obj = agg.setdefault(
            "ai_audit",
            {
                "phase": "baseline+agentic",
                "baseline_finished_at": baseline_finished_at,
                "planner": {
                    "type": "tool_calling" if llm_plan else "disabled",
                    "plans": [],
                    "error": None,
                    "warning": None,
                },
                "planner_mode": "iterative",
                "decision_trace_version": 1,
                "decision_trace": [],
                "max_actions": int(max_actions),
                "actions": [],
                "notes": "",
            },
        )
        if normalized_compliance:
            ai_obj["compliance_profile"] = normalized_compliance
            if compliance_label:
                ai_obj["compliance_framework"] = compliance_label
            if isinstance(compliance_focus, str) and compliance_focus.strip():
                ai_obj["compliance_focus"] = compliance_focus.strip()
            note_text = compliance_label or normalized_compliance
            ai_obj["notes"] = (ai_obj.get("notes") or "").strip()
            compliance_note = f"Compliance profile requested: {note_text}"
            if ai_obj["notes"]:
                if compliance_note not in ai_obj["notes"]:
                    ai_obj["notes"] = f"{ai_obj['notes']} | {compliance_note}"
            else:
                ai_obj["notes"] = compliance_note
        ai_obj.setdefault("planner_mode", "iterative")
        ai_obj.setdefault("decision_trace_version", 1)
        if not isinstance(ai_obj.get("decision_trace"), list):
            ai_obj["decision_trace"] = []

        # Mark baseline results for visibility.
        for entry in agg.get("results", []) or []:
            if isinstance(entry, dict):
                entry.setdefault("phase", "baseline")

        # Phase 2: Agentic expansion (best-effort; bounded)
        llm_enabled = bool(use_llm) and self._llm_enabled(default=True)
        if llm_plan and not llm_enabled:
            llm_plan = False
            ai_obj["planner"]["warning"] = "LLM disabled; skipping agentic phase"

        # Reflect actual LLM usage in the combined report (baseline intentionally runs with use_llm=False).
        if llm_enabled:
            llm_obj = agg.setdefault("llm", {})
            llm_obj["enabled"] = True
            if "reason" in llm_obj:
                llm_obj.pop("reason", None)
            llm_obj.setdefault("calls", [])

        # Use capped/tuned settings from the baseline (aggressive caps may have adjusted values).
        try:
            tuning = agg.get("tuning", {}) if isinstance(agg.get("tuning"), dict) else {}
            tuned_nuclei = tuning.get("nuclei_rate_limit")
            if tuned_nuclei is not None:
                nuclei_rate_limit = int(tuned_nuclei)
            if not nuclei_tags:
                tuned_tags = tuning.get("nuclei_tags")
                if isinstance(tuned_tags, str) and tuned_tags.strip():
                    nuclei_tags = tuned_tags.strip()
            if not nuclei_severity:
                tuned_sev = tuning.get("nuclei_severity")
                if isinstance(tuned_sev, str) and tuned_sev.strip():
                    nuclei_severity = tuned_sev.strip()
            tuned_gobuster = tuning.get("gobuster_threads")
            if tuned_gobuster is not None:
                gobuster_threads = int(tuned_gobuster)
            tuned_wordlist = tuning.get("gobuster_wordlist")
            if isinstance(tuned_wordlist, str) and tuned_wordlist.strip():
                gobuster_wordlist = tuned_wordlist.strip()
        except Exception:
            pass

        web_targets = agg.get("web_targets")
        if not isinstance(web_targets, list):
            web_targets = []
        web_targets = [str(u).strip() for u in web_targets if isinstance(u, str) and u.strip()]
        nmap_cfg = self._tool_config("nmap")
        expand_scope_raw = nmap_cfg.get("url_target_expand_web_scope")
        if isinstance(expand_scope_raw, str):
            url_target_expand_web_scope = expand_scope_raw.strip().lower() in {"1", "true", "yes", "on"}
        elif expand_scope_raw is None:
            url_target_expand_web_scope = False
        else:
            url_target_expand_web_scope = bool(expand_scope_raw)
        lock_web_targets = bool(web_targets) if (normalized.get("base_url") and not url_target_expand_web_scope) else False
        scan_host = str(agg.get("scan_host") or target).strip()

        # Optionally merge nmap-derived web targets when URL scope lock is not active.
        if not lock_web_targets:
            try:
                scan_data = None
                for entry in agg.get("results", []) or []:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("tool") != "nmap" or not entry.get("success"):
                        continue
                    data = entry.get("data")
                    if not isinstance(data, dict):
                        continue
                    maybe_scan = data.get("scan_data")
                    if isinstance(maybe_scan, dict):
                        scan_data = maybe_scan
                        break
                if isinstance(scan_data, dict) and scan_data:
                    for u in self._web_targets_from_nmap(scan_host, scan_data):
                        if u not in web_targets:
                            web_targets.append(u)
            except Exception:
                pass
        web_targets = self._scope_web_targets_for_target(
            normalized,
            web_targets,
            expand_web_scope=bool(url_target_expand_web_scope),
        )
        agg["web_targets"] = web_targets

        baseline_web = web_targets[0] if web_targets else None
        extra_web_targets = [u for u in web_targets if u != baseline_web]

        if extra_web_targets:
            ai_obj["notes"] = f"Additional web targets detected: {', '.join(extra_web_targets[:6])}"

        # Agentic tool-calling phase (bounded).
        agentic_enabled = bool(llm_plan)
        coverage_debt_pivot_count = 0
        ai_obj["planner"]["type"] = "tool_calling" if agentic_enabled else "disabled"

        if not agentic_enabled:
            ai_obj["planner"]["warning"] = "Agentic phase disabled (--no-llm-plan)."
            ai_obj["agentic_skipped"] = True
        elif not llm_enabled:
            ai_obj["planner"]["warning"] = "LLM disabled; skipping agentic phase."
            ai_obj["agentic_skipped"] = True
        else:
            compliance_profiles = self._compliance_profiles()
            profile_values = ("fast", "standard", "aggressive") + tuple(compliance_profiles.keys())
            requested_compliance = normalized_compliance if normalized_compliance in compliance_profiles else None
            open_ports: List[int] = []
            nmap_scan_data: Dict[str, Any] = {}
            try:
                for entry in agg.get("results", []) or []:
                    if isinstance(entry, dict) and entry.get("tool") == "nmap" and entry.get("success"):
                        scan_data = entry.get("data", {}).get("scan_data", {}) if isinstance(entry.get("data"), dict) else {}
                        if isinstance(scan_data, dict):
                            nmap_scan_data = scan_data
                        open_ports = self._open_ports_from_nmap(scan_data if isinstance(scan_data, dict) else {})
                        break
            except Exception:
                open_ports = []

            tls_ports = self._tls_candidate_ports_from_nmap(nmap_scan_data, web_targets=web_targets)
            smb_ports = [p for p in open_ports if p in (139, 445)]

            allowed_web_targets = [u for u in web_targets if isinstance(u, str) and u.strip()]
            sqlmap_cfg = self._tool_config("sqlmap")
            try:
                sqlmap_max_targets = int(sqlmap_cfg.get("max_targets", 2))
            except Exception:
                sqlmap_max_targets = 2
            sqlmap_max_targets = max(1, min(sqlmap_max_targets, 8))
            sqlmap_plan = self._build_sqlmap_targets(
                normalized,
                web_targets=allowed_web_targets,
                results=agg.get("results", []),
                max_targets=sqlmap_max_targets,
                return_plan=True,
            )
            sqlmap_targets = (
                list(sqlmap_plan.get("targets", []))
                if isinstance(sqlmap_plan, dict) and isinstance(sqlmap_plan.get("targets"), list)
                else []
            )
            sqlmap_rejected_targets: Set[str] = set()
            if isinstance(sqlmap_plan, dict):
                for item in sqlmap_plan.get("rejected_targets", []) or []:
                    value = str(item or "").strip()
                    if value:
                        sqlmap_rejected_targets.add(value)

            tool_specs = {
                "httpx": {"target_kind": "web", "enabled_default": True},
                "whatweb": {"target_kind": "web", "enabled_default": True},
                "nuclei": {"target_kind": "web", "enabled_default": True},
                "gobuster": {"target_kind": "web", "enabled_default": True},
                "ffuf": {"target_kind": "web", "enabled_default": False},
                "katana": {"target_kind": "web", "enabled_default": False},
                "browser_use": {"target_kind": "web", "enabled_default": True},
                "nikto": {"target_kind": "web", "enabled_default": False, "opt_in": bool(run_nikto)},
                "sqlmap": {"target_kind": "web", "enabled_default": True, "requires_param": True},
                "dnsenum": {"target_kind": "domain", "enabled_default": True},
                "subfinder": {"target_kind": "domain", "enabled_default": False},
                "sslscan": {"target_kind": "host_port", "enabled_default": True},
                "enum4linux-ng": {"target_kind": "host", "enabled_default": True, "requires_smb": True},
                "trivy": {"target_kind": "container", "enabled_default": True},
            }

            browser_use_cfg = self._tool_config("browser_use")
            browser_use_command = str(browser_use_cfg.get("command") or "").strip()
            browser_use_available = False
            if self._has_scanner("browser_use"):
                browser_use_scanner = self.scanners.get("browser_use")
                checker = getattr(browser_use_scanner, "is_available", None)
                if callable(checker):
                    try:
                        browser_use_available = bool(checker(command_override=browser_use_command or None))
                    except Exception:
                        browser_use_available = False

            allowed_tools: List[str] = []
            for tool, spec in tool_specs.items():
                if not self._has_scanner(tool):
                    continue
                if not self._tool_enabled(tool, default=bool(spec.get("enabled_default", True))):
                    continue
                if spec.get("opt_in") is False:
                    continue
                if tool in ("dnsenum", "subfinder") and not self._should_run_dnsenum(scan_host):
                    continue
                if tool == "sslscan" and not tls_ports:
                    continue
                if tool == "enum4linux-ng" and not smb_ports:
                    continue
                if tool == "trivy" and not container_image:
                    continue
                if tool == "browser_use" and not run_browser_use:
                    continue
                if tool == "browser_use" and (not allowed_web_targets or not browser_use_available):
                    continue
                allowed_tools.append(tool)

            baseline_success: set[tuple] = set()
            baseline_broad_nuclei_targets: Set[str] = set()
            for entry in agg.get("results", []) or []:
                if not isinstance(entry, dict) or not entry.get("success"):
                    continue
                entry_tool = str(entry.get("tool") or "").strip().lower()
                if tool_specs.get(entry_tool, {}).get("target_kind") != "web":
                    continue
                if entry_tool == "httpx":
                    alive = entry.get("data", {}).get("alive")
                    if isinstance(alive, list):
                        for u in alive:
                            u = str(u).strip()
                            if u:
                                baseline_success.add((entry_tool, u))
                targets = entry.get("targets")
                if isinstance(targets, list):
                    for u in targets:
                        v = str(u).strip()
                        if v:
                            if entry_tool == "nuclei" and str(entry.get("target_scope") or "").strip().lower() == "broad":
                                baseline_broad_nuclei_targets.add(v)
                                continue
                            baseline_success.add((entry_tool, v))
                target = entry.get("target")
                if isinstance(target, str) and target.strip():
                    baseline_success.add((entry_tool, target.strip()))

            if not allowed_tools:
                ai_obj["planner"]["warning"] = "No eligible tools available for agentic phase."
                ai_obj["agentic_skipped"] = True
            else:
                allowed_argument_keys = {
                    "profile",
                    "target",
                    "port",
                    "rate_limit",
                    "threads",
                    "wordlist",
                    "task",
                    "max_steps",
                    "headless",
                    "model",
                    "browser_session",
                    "browser_profile",
                }

                def _as_bool(value: Any, default: bool = False) -> bool:
                    if isinstance(value, bool):
                        return value
                    if isinstance(value, str):
                        txt = value.strip().lower()
                        if txt in {"1", "true", "yes", "on"}:
                            return True
                        if txt in {"0", "false", "no", "off"}:
                            return False
                    return bool(default)

                def _resolve_secret(value: Any, env_name: Any = None) -> str:
                    if isinstance(env_name, str) and env_name.strip():
                        env_val = os.getenv(env_name.strip())
                        if isinstance(env_val, str) and env_val.strip():
                            return env_val.strip()
                    if isinstance(value, str) and value.strip():
                        return value.strip()
                    return ""

                def _browser_use_auth_context(cfg: Dict[str, Any]) -> Dict[str, Any]:
                    auth_cfg = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else {}
                    enabled = _as_bool(auth_cfg.get("enabled"), False)
                    include_secrets = _as_bool(auth_cfg.get("include_secrets_in_task"), False)
                    login_url = str(auth_cfg.get("login_url") or "").strip()
                    notes = str(auth_cfg.get("notes") or "").strip()
                    username = _resolve_secret(auth_cfg.get("username"), auth_cfg.get("username_env"))
                    password = _resolve_secret(auth_cfg.get("password"), auth_cfg.get("password_env"))
                    cookie = _resolve_secret(auth_cfg.get("cookie"), auth_cfg.get("cookie_env"))
                    has_creds = bool(username and password)
                    has_cookie = bool(cookie)
                    return {
                        "enabled": bool(enabled),
                        "include_secrets_in_task": bool(include_secrets),
                        "login_url": login_url,
                        "notes": notes,
                        "credentials_configured": bool(has_creds),
                        "cookie_configured": bool(has_cookie),
                        "has_auth_context": bool(enabled and (login_url or has_creds or has_cookie or notes)),
                        "username": username if include_secrets else "",
                        "password": password if include_secrets else "",
                        "cookie": cookie if include_secrets else "",
                    }

                def _auto_browser_session_name(target_url: str) -> str:
                    text = str(target_url or "").strip()
                    host = ""
                    if text:
                        parse_input = text if "://" in text else f"http://{text}"
                        try:
                            parsed = urlparse(parse_input)
                            host = str(parsed.hostname or "").strip().lower()
                        except Exception:
                            host = ""
                    host = re.sub(r"[^a-z0-9]+", "-", host).strip("-") if host else "target"
                    if not host:
                        host = "target"
                    return f"supabash-{host}-{int(time.time())}"

                browser_default_session = str(browser_use_cfg.get("session") or "").strip() or None
                browser_default_profile = str(browser_use_cfg.get("profile") or "").strip() or None
                browser_auth_default = _browser_use_auth_context(browser_use_cfg)
                browser_auto_session_default = _as_bool(browser_use_cfg.get("auto_session"), True)
                browser_allow_fallback_default = _as_bool(
                    browser_use_cfg.get("allow_deterministic_fallback"), True
                )
                try:
                    browser_deterministic_max_paths_default = int(browser_use_cfg.get("deterministic_max_paths", 8))
                except Exception:
                    browser_deterministic_max_paths_default = 8
                browser_deterministic_max_paths_default = max(
                    1, min(int(browser_deterministic_max_paths_default), 24)
                )
                if not isinstance(ai_obj.get("planner_context_history"), list):
                    ai_obj["planner_context_history"] = []
                planner_context_history: List[Dict[str, Any]] = ai_obj.get("planner_context_history") or []

                def build_tool_schema(allowed: List[str]) -> Dict[str, Any]:
                    return {
                        "type": "function",
                        "function": {
                            "name": "propose_actions",
                            "description": "Propose next audit actions using allowed tools and targets.",
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "actions": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "tool_name": {"type": "string", "enum": allowed},
                                                "arguments": {
                                                    "type": "object",
                                                    "properties": {
                                                        "profile": {
                                                            "type": "string",
                                                            "enum": list(profile_values),
                                                        },
                                                        "target": {"type": "string"},
                                                        "port": {"type": "integer"},
                                                        "rate_limit": {"type": "integer"},
                                                        "threads": {"type": "integer"},
                                                        "wordlist": {"type": "string"},
                                                        "task": {"type": "string"},
                                                        "max_steps": {"type": "integer"},
                                                        "headless": {"type": "boolean"},
                                                        "model": {"type": "string"},
                                                        "browser_session": {"type": "string"},
                                                        "browser_profile": {"type": "string"},
                                                    },
                                                    "required": ["profile"],
                                                    "additionalProperties": False,
                                                },
                                                "reasoning": {"type": "string"},
                                                "hypothesis": {"type": "string"},
                                                "expected_evidence": {"type": "string"},
                                                "priority": {"type": "integer", "minimum": 1, "maximum": 100},
                                            },
                                            "required": ["tool_name", "arguments", "reasoning"],
                                            "additionalProperties": False,
                                        },
                                    },
                                    "stop": {"type": "boolean"},
                                    "notes": {"type": "string"},
                                },
                                "required": ["actions"],
                                "additionalProperties": False,
                            },
                        },
                    }

                def clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
                    try:
                        v = int(value)
                    except Exception:
                        v = default
                    if v < minimum:
                        return minimum
                    if v > maximum:
                        return maximum
                    return v

                def apply_profile(profile: str, base_rate: int, base_threads: int) -> Tuple[int, int]:
                    prof = (profile or "").strip().lower()
                    if prof not in profile_values:
                        prof = "standard"
                    rate = base_rate
                    threads = base_threads
                    if prof in compliance_profiles:
                        settings = compliance_profiles.get(prof, {})
                        rate = int(settings.get("rate_limit", base_rate))
                        threads = int(settings.get("threads", base_threads))
                        return rate, threads
                    if prof == "fast":
                        threads = max(5, threads // 2)
                        if rate > 0:
                            rate = max(1, rate // 2)
                    elif prof == "aggressive":
                        threads = min(max(threads, 10) * 2, 50)
                        if rate > 0:
                            rate = min(rate * 2, 100)
                    return rate, threads

                def _web_target_host_port_key(value: Any) -> Optional[Tuple[str, int]]:
                    text = str(value or "").strip()
                    if not text:
                        return None
                    parse_input = text if "://" in text else f"http://{text}"
                    try:
                        parsed = urlparse(parse_input)
                        scheme = str(parsed.scheme or "http").strip().lower() or "http"
                        host = str(parsed.hostname or "").strip().lower()
                        if host in {"localhost", "::1"}:
                            host = "127.0.0.1"
                        if not host:
                            return None
                        port = int(parsed.port or (443 if scheme == "https" else 80))
                        return (host, port)
                    except Exception:
                        return None

                def _preferred_allowed_web_target(host_port: Tuple[str, int]) -> Optional[str]:
                    candidates: List[str] = []
                    for item in allowed_web_targets or []:
                        item_text = str(item or "").strip()
                        if not item_text:
                            continue
                        if _web_target_host_port_key(item_text) == host_port:
                            candidates.append(item_text)
                    if not candidates:
                        return None

                    def _rank(value: str) -> Tuple[int, int]:
                        try:
                            parsed = urlparse(value)
                            path = str(parsed.path or "").strip()
                            path_weight = 1 if path and path != "/" else 0
                        except Exception:
                            path_weight = 1
                        return (path_weight, len(value))

                    candidates.sort(key=_rank)
                    return candidates[0]

                def _preserve_allowed_web_target_path(target: str) -> Optional[str]:
                    text = str(target or "").strip()
                    if not text:
                        return None
                    parse_input = text if "://" in text else f"http://{text}"
                    try:
                        parsed = urlparse(parse_input)
                        scheme = str(parsed.scheme or "http").strip().lower() or "http"
                        host = str(parsed.hostname or "").strip().lower()
                        if host in {"localhost", "::1"}:
                            host = "127.0.0.1"
                        if scheme not in ("http", "https") or not host:
                            return None
                        port = int(parsed.port or (443 if scheme == "https" else 80))
                    except Exception:
                        return None
                    preferred = _preferred_allowed_web_target((host, port))
                    if preferred is None:
                        return None
                    chosen_scheme = scheme
                    chosen_host = host
                    chosen_port = port
                    try:
                        preferred_parsed = urlparse(preferred)
                        preferred_scheme = str(preferred_parsed.scheme or "").strip().lower()
                        preferred_host = str(preferred_parsed.hostname or "").strip().lower() or host
                        preferred_port = int(
                            preferred_parsed.port or (443 if preferred_scheme == "https" else 80)
                        )
                        chosen_scheme = preferred_scheme or scheme
                        chosen_host = preferred_host or host
                        chosen_port = preferred_port
                    except Exception:
                        pass
                    path = str(parsed.path or "")
                    if not path and (text.endswith("/") or parse_input.endswith("/")):
                        path = "/"
                    query = str(parsed.query or "")
                    default_port = 443 if chosen_scheme == "https" else 80
                    netloc = chosen_host if chosen_port == default_port else f"{chosen_host}:{chosen_port}"
                    return urlunparse((chosen_scheme, netloc, path, "", query, ""))

                def _canonicalize_web_action_target(tool: str, target: str) -> str:
                    text = str(target or "").strip()
                    if not text:
                        return text
                    tool_name = str(tool or "").strip().lower()
                    if tool_name in ("sqlmap", "browser_use"):
                        return text
                    preserved = _preserve_allowed_web_target_path(text)
                    if preserved:
                        try:
                            parsed = urlparse(preserved)
                            if (
                                (str(parsed.path or "").strip() and str(parsed.path or "").strip() != "/")
                                or str(parsed.query or "").strip()
                                or text.endswith("/")
                            ):
                                return preserved
                        except Exception:
                            return preserved
                    host_port = _web_target_host_port_key(text)
                    if host_port is None:
                        return text
                    mapped = _preferred_allowed_web_target(host_port)
                    if mapped:
                        return mapped
                    parse_input = text if "://" in text else f"http://{text}"
                    try:
                        parsed = urlparse(parse_input)
                        scheme = str(parsed.scheme or "http").strip().lower() or "http"
                        host = str(parsed.hostname or "").strip().lower()
                        if not host:
                            return text
                        default_port = 443 if scheme == "https" else 80
                        port = int(parsed.port or default_port)
                        if port == default_port:
                            return f"{scheme}://{host}"
                        return f"{scheme}://{host}:{port}"
                    except Exception:
                        return text

                def _resolve_allowed_web_target(tool: str, target: str) -> Optional[str]:
                    text = str(target or "").strip()
                    if not text:
                        return None
                    tool_name = str(tool or "").strip().lower()
                    if tool_name == "browser_use":
                        preserved = _preserve_allowed_web_target_path(text)
                        if preserved:
                            return preserved
                        if text in allowed_web_targets:
                            return text
                        parse_input = text if "://" in text else f"http://{text}"
                        try:
                            parsed = urlparse(parse_input)
                            scheme = str(parsed.scheme or "").strip().lower()
                            host = str(parsed.hostname or "").strip().lower()
                            if host in {"localhost", "::1"}:
                                host = "127.0.0.1"
                            if scheme not in ("http", "https") or not host:
                                return None
                            port = int(parsed.port or (443 if scheme == "https" else 80))
                        except Exception:
                            return None
                        host_port = (host, port)
                        preferred = _preferred_allowed_web_target(host_port)
                        if preferred is None:
                            return None
                        return preserved or preferred
                    if tool_name == "sqlmap":
                        if text in sqlmap_targets:
                            normalized_candidate = self._normalize_sqlmap_candidate_url(text)
                            if normalized_candidate and normalized_candidate in sqlmap_rejected_targets:
                                return None
                            return text
                        parse_input = text if "://" in text else f"http://{text}"
                        host_scope = set()
                        normalized_host = str(normalized.get("host") or "").strip().lower()
                        if normalized_host:
                            host_scope.add(normalized_host)
                        for item in allowed_web_targets or []:
                            hp = _web_target_host_port_key(item)
                            if hp is not None and hp[0]:
                                host_scope.add(hp[0])
                        normalized_candidate = self._normalize_sqlmap_candidate_url(
                            parse_input,
                            allowed_hosts=host_scope,
                        )
                        if not normalized_candidate:
                            return None
                        if normalized_candidate in sqlmap_rejected_targets:
                            return None
                        return normalized_candidate
                    if text in allowed_web_targets:
                        return text
                    preserved = _preserve_allowed_web_target_path(text)
                    if preserved:
                        try:
                            parsed = urlparse(preserved)
                            if (
                                (str(parsed.path or "").strip() and str(parsed.path or "").strip() != "/")
                                or str(parsed.query or "").strip()
                                or text.endswith("/")
                            ):
                                return preserved
                        except Exception:
                            return preserved
                    host_port = _web_target_host_port_key(text)
                    if host_port is None:
                        return None
                    return _preferred_allowed_web_target(host_port)

                def _extract_result_error_text(entry: Any) -> str:
                    if not isinstance(entry, dict):
                        return ""
                    pieces: List[str] = []
                    direct_error = str(entry.get("error") or "").strip()
                    if direct_error:
                        pieces.append(direct_error)
                    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
                    data_error = str(data.get("error") or "").strip() if isinstance(data, dict) else ""
                    if data_error and data_error not in pieces:
                        pieces.append(data_error)
                    reason = str(entry.get("reason") or "").strip()
                    if reason and reason not in pieces:
                        pieces.append(reason)
                    return " ".join(pieces).strip().lower()

                def _is_gobuster_wildcard_error(entry: Any) -> bool:
                    text = _extract_result_error_text(entry)
                    if not text:
                        return False
                    patterns = (
                        "the server returns a status code that matches",
                        "non existing urls",
                        "use the --wildcard switch",
                        "please exclude the status code",
                        "wildcard",
                        "soft-404",
                    )
                    return any(pattern in text for pattern in patterns)

                def _urls_from_text(value: Any) -> List[str]:
                    text = str(value or "").strip()
                    if not text:
                        return []
                    return [
                        str(x).rstrip(".,;)]>}\"'")
                        for x in re.findall(r"https?://[^\s)>'\"`]+", text, flags=re.IGNORECASE)
                    ]

                def _strip_browser_url_artifacts(value: Any) -> str:
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

                def _sanitize_browser_url_candidate(value: Any, *, base_target: str = "") -> str:
                    text = _strip_browser_url_artifacts(value)
                    if not text.startswith(("http://", "https://")):
                        return ""
                    try:
                        parsed = urlparse(text)
                    except Exception:
                        return ""
                    if not parsed.scheme or not parsed.netloc:
                        return ""
                    if base_target:
                        try:
                            parsed_base = urlparse(str(base_target or "").strip())
                        except Exception:
                            parsed_base = None
                        if parsed_base and parsed_base.netloc == parsed.netloc:
                            path = re.sub(r"/{2,}", "/", str(parsed.path or "/"))
                            if path.startswith("//"):
                                return ""
                            text = f"{parsed.scheme}://{parsed.netloc}{path}"
                            if parsed.query:
                                text = f"{text}?{parsed.query}"
                    return text

                def _sanitize_browser_urls_in_text(value: Any, *, base_target: str = "") -> str:
                    text = str(value or "")
                    if not text:
                        return ""

                    def repl(match: re.Match) -> str:
                        raw = str(match.group(0) or "")
                        sanitized = _sanitize_browser_url_candidate(raw, base_target=base_target)
                        return sanitized if sanitized else _strip_browser_url_artifacts(raw)

                    return re.sub(r"https?://[^\s'\"<>`]+", repl, text, flags=re.IGNORECASE)

                def _normalize_browser_scope_path(value: Any) -> str:
                    text = str(value or "").strip() or "/"
                    if "?" in text:
                        path_part, query_part = text.split("?", 1)
                        path_part = path_part.rstrip("/") or "/"
                        return f"{path_part}?{query_part}"
                    return text.rstrip("/") or "/"

                def _browser_paths_related(target_path: str, candidate_path: str) -> bool:
                    a = _normalize_browser_scope_path(target_path)
                    b = _normalize_browser_scope_path(candidate_path)
                    if a == b:
                        return True
                    a_path = a.split("?", 1)[0]
                    b_path = b.split("?", 1)[0]
                    if a_path == "/" or b_path == "/":
                        return True
                    if b_path.startswith(a_path.rstrip("/") + "/"):
                        return True
                    if a_path.startswith(b_path.rstrip("/") + "/"):
                        return True
                    return False

                def _finding_matches_browser_scope(item: Dict[str, Any], *, target_url: str) -> bool:
                    if not isinstance(item, dict):
                        return False
                    base_hp = _web_target_host_port_key(target_url)
                    if base_hp is None:
                        return False
                    try:
                        parsed_target = urlparse(str(target_url or "").strip())
                        target_path = _normalize_browser_scope_path(
                            f"{str(parsed_target.path or '/').strip() or '/'}"
                            + (f"?{parsed_target.query}" if parsed_target.query else "")
                        )
                    except Exception:
                        target_path = "/"

                    matched_same_origin = False
                    candidate_texts = [
                        item.get("target"),
                        item.get("evidence"),
                        item.get("title"),
                    ]
                    for raw in candidate_texts:
                        text = str(raw or "").strip()
                        if not text:
                            continue
                        direct = [text] if text.startswith(("http://", "https://")) else []
                        for url in direct + _urls_from_text(text):
                            hp = _web_target_host_port_key(url)
                            if hp != base_hp:
                                continue
                            matched_same_origin = True
                            try:
                                parsed = urlparse(url)
                                candidate_path = _normalize_browser_scope_path(
                                    f"{str(parsed.path or '/').strip() or '/'}"
                                    + (f"?{parsed.query}" if parsed.query else "")
                                )
                            except Exception:
                                candidate_path = "/"
                            if _browser_paths_related(target_path, candidate_path):
                                return True
                    if matched_same_origin:
                        return True
                    combined = " ".join(str(x or "").strip() for x in candidate_texts).lower()
                    return target_url.lower() in combined

                def _target_related_findings_for_browser(target_url: str, limit: int = 6) -> List[Dict[str, str]]:
                    selected: List[Dict[str, str]] = []
                    seen: Set[str] = set()
                    findings_all: List[Dict[str, Any]] = []
                    try:
                        collected = self._collect_findings(agg)
                        findings_all = collected if isinstance(collected, list) else []
                    except Exception:
                        findings_all = []

                    for item in reversed(findings_all):
                        if not isinstance(item, dict):
                            continue
                        title = str(item.get("title") or "").strip()
                        evidence = str(item.get("evidence") or "").strip()
                        severity = str(item.get("severity") or "INFO").strip().upper()
                        risk_class = str(item.get("risk_class") or "").strip().lower()
                        if not _finding_matches_browser_scope(item, target_url=target_url):
                            continue
                        key = f"{severity}|{title}|{risk_class}"
                        if key in seen:
                            continue
                        seen.add(key)
                        selected.append(
                            {
                                "severity": severity,
                                "title": title[:120],
                                "evidence": evidence[:200],
                                "risk_class": risk_class[:60],
                            }
                        )
                        if len(selected) >= max(1, int(limit)):
                            break
                    selected.reverse()
                    return selected

                def _build_browser_use_task(
                    action: Dict[str, Any],
                    *,
                    target_url: str,
                    proposed_task: Optional[str],
                    auth_ctx: Dict[str, Any],
                ) -> str:
                    reasoning = str(action.get("reasoning") or "").strip()
                    hypothesis = str(action.get("hypothesis") or "").strip()
                    expected = str(action.get("expected_evidence") or "").strip()
                    prior_findings = _target_related_findings_for_browser(target_url, limit=6)

                    lines: List[str] = [
                        "Perform a focused browser-driven security validation.",
                        f"Target URL: {target_url}",
                    ]
                    if proposed_task:
                        lines.append(f"Planner objective: {proposed_task}")
                    if reasoning:
                        lines.append(f"Rationale: {reasoning}")
                    if hypothesis:
                        lines.append(f"Hypothesis: {hypothesis}")
                    if expected:
                        lines.append(f"Expected evidence: {expected}")

                    if prior_findings:
                        lines.append("Prior findings to validate:")
                        for item in prior_findings:
                            sev = str(item.get("severity") or "INFO")
                            title = str(item.get("title") or "").strip()
                            ev = str(item.get("evidence") or "").strip()
                            lines.append(f"- [{sev}] {title}: {ev}")

                    lines.extend(
                        [
                            "Execution guidance:",
                            "- Start at the target URL and map reachable same-origin paths/forms.",
                            "- Stay on the target origin (same host:port) unless the selected target itself redirects there.",
                            "- For each discovered form, capture action URL, method, parameter names, and client-side validation clues.",
                            "- Trace likely backing API endpoints (XHR/fetch paths, REST/GraphQL routes, form action targets) and note auth behavior.",
                            "- Validate auth barriers, default/admin entry points, debug/error disclosures, and session behavior.",
                            "- Do not brute-force credentials or run destructive actions.",
                            "- Collect concrete evidence: visited URLs, page titles, auth prompts/barriers, status/redirect clues, and any stack traces/errors.",
                        ]
                    )

                    if bool(auth_ctx.get("has_auth_context")):
                        lines.append("Authentication context is configured for this run.")
                        login_url = str(auth_ctx.get("login_url") or "").strip()
                        notes = str(auth_ctx.get("notes") or "").strip()
                        if login_url:
                            lines.append(f"- Preferred login URL: {login_url}")
                        if bool(auth_ctx.get("credentials_configured")):
                            if bool(auth_ctx.get("include_secrets_in_task")):
                                username = str(auth_ctx.get("username") or "").strip()
                                password = str(auth_ctx.get("password") or "").strip()
                                if username:
                                    lines.append(f"- Username: {username}")
                                if password:
                                    lines.append(f"- Password: {password}")
                            else:
                                lines.append("- Credentials are configured (not included here); use configured auth context safely.")
                        if bool(auth_ctx.get("cookie_configured")):
                            if bool(auth_ctx.get("include_secrets_in_task")):
                                cookie = str(auth_ctx.get("cookie") or "").strip()
                                if cookie:
                                    lines.append(f"- Session cookie: {cookie}")
                            else:
                                lines.append("- Session cookie context is configured (not included here).")
                        if notes:
                            lines.append(f"- Auth notes: {notes}")
                    else:
                        lines.append("Run unauthenticated workflow validation only.")

                    lines.append(
                        "Output requirements: provide concise evidence lines suitable for audit reporting; include endpoints and observations, not generic prose."
                    )
                    return "\n".join(lines)[:5000]

                def normalize_action(item: Any) -> Optional[Dict[str, Any]]:
                    if not isinstance(item, dict):
                        return None
                    tool = str(item.get("tool_name") or "").strip().lower()
                    if tool not in allowed_tools:
                        return None
                    args = item.get("arguments")
                    if not isinstance(args, dict):
                        return None
                    profile = str(args.get("profile") or "standard").strip().lower()
                    if profile not in profile_values:
                        profile = "standard"
                    if requested_compliance and profile != requested_compliance:
                        profile = requested_compliance
                    filtered = {k: v for k, v in args.items() if k in allowed_argument_keys}
                    filtered["profile"] = profile
                    raw_target = filtered.get("target")
                    if isinstance(raw_target, str) and raw_target.strip():
                        filtered["target"] = _canonicalize_web_action_target(tool, raw_target)
                    reasoning = str(item.get("reasoning") or "").strip()
                    hypothesis = str(item.get("hypothesis") or "").strip()
                    expected_evidence = str(item.get("expected_evidence") or "").strip()
                    priority = clamp_int(item.get("priority"), default=50, minimum=1, maximum=100)
                    return {
                        "tool": tool,
                        "arguments": filtered,
                        "profile": profile,
                        "reasoning": reasoning,
                        "hypothesis": hypothesis,
                        "expected_evidence": expected_evidence,
                        "priority": priority,
                    }

                def resolve_wordlist(value: Optional[str]) -> Optional[str]:
                    if not value or not isinstance(value, str):
                        return None
                    candidate = value.strip()
                    if not candidate:
                        return None
                    path = Path(candidate).expanduser()
                    if not path.is_absolute():
                        data_dir = Path(__file__).resolve().parent / "data" / "wordlists"
                        path = data_dir / candidate
                    return str(path) if path.exists() else None

                tls_port_set: Set[int] = set()
                for p in tls_ports or []:
                    try:
                        tls_port_set.add(int(p))
                    except Exception:
                        continue
                tls_ports_nmap_only = self._tls_candidate_ports_from_nmap(nmap_scan_data, web_targets=None)
                tls_port_set_strict: Set[int] = set()
                for p in tls_ports_nmap_only or []:
                    try:
                        tls_port_set_strict.add(int(p))
                    except Exception:
                        continue

                def _extract_port_from_target_hint(value: Any) -> Optional[int]:
                    text = str(value or "").strip()
                    if not text:
                        return None
                    try:
                        parsed = urlparse(text)
                        if parsed.scheme:
                            if parsed.port:
                                return int(parsed.port)
                            if (parsed.scheme or "").lower() == "https":
                                return 443
                    except Exception:
                        pass
                    port_match = re.search(r":(\d{2,5})$", text)
                    if port_match:
                        try:
                            return int(port_match.group(1))
                        except Exception:
                            return None
                    return None

                def _resolve_sslscan_port_for_action(action: Dict[str, Any], result_entry: Optional[Dict[str, Any]] = None) -> Optional[int]:
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    port_hint: Any = None
                    if isinstance(result_entry, dict) and result_entry.get("port") is not None:
                        port_hint = result_entry.get("port")
                    if port_hint is None:
                        port_hint = args.get("port")
                    if port_hint is None:
                        port_hint = _extract_port_from_target_hint(args.get("target"))

                    if port_hint is not None:
                        try:
                            requested = int(port_hint)
                        except Exception:
                            requested = None
                        if requested is None:
                            return None
                        if tls_port_set_strict and requested not in tls_port_set_strict:
                            return None
                        if (not tls_port_set_strict) and tls_port_set and requested not in tls_port_set:
                            return None
                        return requested

                    if tls_ports_nmap_only:
                        try:
                            return int(tls_ports_nmap_only[0])
                        except Exception:
                            return None
                    if tls_ports:
                        try:
                            return int(tls_ports[0])
                        except Exception:
                            return None
                    return None

                def parse_tool_calls(tool_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
                    actions: List[Dict[str, Any]] = []
                    notes = ""
                    stop = False
                    for call in tool_calls:
                        if call.get("name") != "propose_actions":
                            continue
                        args = call.get("arguments")
                        if not isinstance(args, dict):
                            raise ToolCallingError("Tool call arguments missing or invalid.")
                        stop = bool(args.get("stop")) or stop
                        note_text = args.get("notes")
                        if isinstance(note_text, str) and note_text.strip():
                            notes = note_text.strip()
                        raw_actions = args.get("actions", [])
                        if raw_actions is None:
                            raw_actions = []
                        if not isinstance(raw_actions, list):
                            raise ToolCallingError("Tool call actions must be a list.")
                        for item in raw_actions:
                            spec = normalize_action(item)
                            if spec:
                                actions.append(spec)
                    return {"actions": actions, "notes": notes, "stop": stop}

                def plan_actions(remaining: int, excluded_actions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
                    results_summary = []
                    for r in agg.get("results", []) or []:
                        if not isinstance(r, dict):
                            continue
                        item_summary: Dict[str, Any] = {
                            "tool": r.get("tool"),
                            "success": r.get("success"),
                            "skipped": r.get("skipped"),
                            "phase": r.get("phase"),
                        }
                        data_block = r.get("data") if isinstance(r.get("data"), dict) else {}
                        if isinstance(data_block, dict):
                            if isinstance(data_block.get("observation"), dict):
                                obs = data_block.get("observation") or {}
                                item_summary["observation"] = {
                                    "done": obs.get("done"),
                                    "steps": obs.get("steps"),
                                    "findings_count": obs.get("findings_count"),
                                    "urls_count": obs.get("urls_count"),
                                }
                            if str(r.get("tool") or "").strip().lower() == "browser_use":
                                item_summary["browser"] = {
                                    "completed": data_block.get("completed"),
                                    "urls": len(data_block.get("urls") or []),
                                    "findings": len(data_block.get("findings") or []),
                                }
                        results_summary.append(item_summary)

                    all_findings: List[Dict[str, Any]] = []
                    try:
                        collected = self._collect_findings(agg)
                        all_findings = collected if isinstance(collected, list) else []
                    except Exception:
                        all_findings = []
                    finding_clusters = _cluster_findings_for_planner(all_findings)

                    findings_recent: List[Dict[str, Any]] = []
                    for f in all_findings[-30:]:
                        if not isinstance(f, dict):
                            continue
                        findings_recent.append(
                            {
                                "severity": str(f.get("severity") or "INFO").strip().upper(),
                                "title": str(f.get("title") or "").strip(),
                                "evidence": str(f.get("evidence") or "").strip()[:240],
                                "tool": str(f.get("tool") or "").strip(),
                                "phase": str(f.get("phase") or "baseline").strip(),
                                "risk_class": str(f.get("risk_class") or "").strip().lower(),
                                "dedup_key": str(f.get("dedup_key") or "").strip(),
                            }
                        )
                        if len(findings_recent) >= 30:
                            break

                    compliance_block = {}
                    if compliance_profiles:
                        compliance_block["profiles"] = {
                            key: {
                                "label": spec.get("label"),
                                "focus": spec.get("focus"),
                                "preferred_tools": spec.get("preferred_tools", []),
                            }
                            for key, spec in compliance_profiles.items()
                        }
                    if requested_compliance:
                        spec = compliance_profiles.get(requested_compliance, {})
                        required_tools = spec.get("required_tools", []) if isinstance(spec.get("required_tools"), list) else []
                        missing_required = [t for t in required_tools if t not in allowed_tools]
                        compliance_block.update(
                            {
                                "requested_profile": requested_compliance,
                                "framework": spec.get("label"),
                                "focus": spec.get("focus"),
                                "required_tools": required_tools,
                                "missing_required_tools": missing_required,
                            }
                        )

                    excluded = []
                    for item in excluded_actions or []:
                        if not isinstance(item, dict):
                            continue
                        args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
                        excluded.append(
                            {
                                "tool": item.get("tool"),
                                "target": args.get("target"),
                                "profile": item.get("profile"),
                                "reason": "already_covered_by_baseline_or_agentic",
                            }
                        )

                    baseline_action_rows = _baseline_action_ledger()
                    agentic_action_rows = _planner_action_ledger_snapshot(limit=120)
                    blocked_recent_rows = [dict(x) for x in planner_blocked_candidates[-120:] if isinstance(x, dict)]
                    context_obj = {
                        "target": target,
                        "mode": mode,
                        "remaining_actions": int(remaining),
                        "planning_objective": {
                            "primary": "Close uncovered high-risk finding clusters first.",
                            "must_link_open_high_risk_cluster": bool(
                                len(finding_clusters.get("open_high_risk_clusters", []) or []) > 0
                            ),
                            "open_high_risk_cluster_count": len(
                                finding_clusters.get("open_high_risk_clusters", []) or []
                            ),
                        },
                        "allowed_tools": allowed_tools,
                        "allowed_targets": {
                            "web": allowed_web_targets[:12],
                            "sqlmap": sqlmap_targets[:6],
                            "scan_host": scan_host,
                        },
                        "open_ports": open_ports,
                        "observations": {
                            "web_targets": allowed_web_targets[:12],
                            "results_recent": results_summary[-20:],
                            "findings_recent": findings_recent,
                        },
                        "findings_state": {
                            "coverage": {
                                "all_findings_included": True,
                                "baseline_and_agentic_included": True,
                                "total_findings": int(finding_clusters.get("total_findings", 0)),
                                "cluster_count": int(finding_clusters.get("cluster_count", 0)),
                            },
                            "open_high_risk_clusters": finding_clusters.get("open_high_risk_clusters", []),
                            "covered_cluster_ids": finding_clusters.get("covered_cluster_ids", []),
                            "clusters": finding_clusters.get("clusters", []),
                        },
                        "actions_state": {
                            "baseline_actions": baseline_action_rows[-80:],
                            "agentic_actions_taken": agentic_action_rows,
                            "blocked_candidates_recent": blocked_recent_rows,
                            "already_done_actions": excluded[:120],
                            "low_signal_streak": int(low_signal_streak),
                            "recent_gain_scores": [int(x) for x in recent_gain_scores[-8:]],
                            "nonpositive_after_broad_streak": int(nonpositive_after_broad_streak),
                            "last_action": agentic_action_rows[-1] if agentic_action_rows else None,
                        },
                        "compliance": compliance_block,
                        "constraints": {
                            "profile_enum": list(profile_values),
                            "sqlmap_requires_parameterized_url": True,
                            "sqlmap_blocked_targets": sorted(sqlmap_rejected_targets)[:20],
                            "nikto_opt_in": bool(run_nikto),
                            "browser_use_enabled": bool(run_browser_use),
                            "browser_use_available": bool(browser_use_available),
                            "browser_use_session_configured": bool(browser_default_session),
                            "browser_use_profile_configured": bool(browser_default_profile),
                            "browser_use_auto_session": bool(browser_auto_session_default),
                            "browser_use_auth_context_enabled": bool(browser_auth_default.get("enabled")),
                            "browser_use_auth_context_available": bool(browser_auth_default.get("has_auth_context")),
                            "browser_use_auth_login_url": str(browser_auth_default.get("login_url") or ""),
                            "browser_use_allow_deterministic_fallback": bool(browser_allow_fallback_default),
                            "browser_use_deterministic_max_paths": int(browser_deterministic_max_paths_default),
                            "trivy_requires_container": bool(container_image),
                            "tls_ports_detected": tls_ports,
                            "smb_ports_detected": bool(smb_ports),
                            "high_risk_web_targets": sorted(_high_risk_web_targets_now())[:8],
                            "baseline_broad_nuclei_targets": sorted(baseline_broad_nuclei_targets)[:24],
                            # Keep this reasonably large so replans can avoid the full
                            # already-covered web surface, not just a tiny subset.
                            "excluded_actions": excluded[:64],
                        },
                    }
                    planner_context_history.append(
                        {
                            "timestamp": time.time(),
                            "remaining_actions": int(remaining),
                            "allowed_tools": list(allowed_tools),
                            "open_ports_count": len(open_ports or []),
                            "web_target_count": len(allowed_web_targets or []),
                            "findings_total": int(finding_clusters.get("total_findings", 0)),
                            "finding_cluster_count": int(finding_clusters.get("cluster_count", 0)),
                            "open_high_risk_cluster_count": len(finding_clusters.get("open_high_risk_clusters", []) or []),
                            "baseline_actions_count": len(baseline_action_rows),
                            "agentic_actions_count": len(agentic_action_rows),
                            "blocked_recent_count": len(blocked_recent_rows),
                            "excluded_actions_count": len(excluded),
                            "last_action": agentic_action_rows[-1] if agentic_action_rows else None,
                            "open_high_risk_clusters": finding_clusters.get("open_high_risk_clusters", [])[:20],
                        }
                    )
                    if len(planner_context_history) > 120:
                        planner_context_history[:] = planner_context_history[-120:]
                    ai_obj["planner_context_history"] = planner_context_history

                    max_chars = self._llm_max_chars(default=12000)
                    payload, truncated = prepare_json_payload(context_obj, max_chars=max_chars)
                    messages = [
                        {"role": "system", "content": prompts.AGENTIC_TOOLCALL_PROMPT},
                        {"role": "user", "content": payload},
                    ]
                    if truncated:
                        messages.insert(1, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

                    note("llm_start", "planner", "Formulating audit expansion plan with tool-calling", agg=agg)
                    tool_calls, meta = self.llm.tool_call(
                        messages,
                        tools=[build_tool_schema(allowed_tools)],
                        tool_choice={"type": "function", "function": {"name": "propose_actions"}},
                    )
                    if isinstance(meta, dict):
                        meta = dict(meta)
                        meta.update(
                            {
                                "call_type": "plan",
                                "stage": "ai_audit_tool_call",
                                "input_truncated": bool(truncated),
                                "input_chars": len(payload),
                                "max_input_chars": int(max_chars),
                            }
                        )
                        self._append_llm_call(agg, meta)

                    return parse_tool_calls(tool_calls)

                def run_agentic_action(action: Dict[str, Any]) -> Dict[str, Any]:
                    tool = action["tool"]
                    args = action["arguments"]
                    profile = action["profile"]
                    target = args.get("target") if isinstance(args.get("target"), str) else None
                    if isinstance(target, str) and target.strip():
                        target = _canonicalize_web_action_target(tool, target)
                        args["target"] = target

                    action_target = None
                    action_port = None

                    if canceled():
                        entry = {"tool": tool, "success": False, "skipped": True, "reason": "Canceled"}
                    elif tool_specs.get(tool, {}).get("target_kind") == "web":
                        resolved_target = _resolve_allowed_web_target(tool, target or "")
                        if not target:
                            entry = self._skip_tool(tool, "Missing target")
                        elif resolved_target is None:
                            entry = self._skip_tool(tool, "Target not in allowed web targets")
                        else:
                            if tool != "sqlmap":
                                target = str(resolved_target)
                                args["target"] = target
                            action_target = target
                            action_key = (tool, action_target or "")
                            if action_key in baseline_success:
                                entry = self._skip_tool(tool, "Already completed in baseline phase")
                            elif action_key in agentic_success:
                                entry = self._skip_tool(tool, "Already completed in agentic phase")
                            else:
                                base_rate = int(nuclei_rate_limit or 0)
                                base_threads = int(gobuster_threads or 10)
                                rate_limit = args.get("rate_limit", base_rate)
                                threads = args.get("threads", base_threads)
                                # Keep planner-suggested rates bounded, but if a baseline/configured
                                # nuclei rate exists, allow that value to flow through unchanged.
                                max_rate = max(100, int(base_rate or 0))
                                rate_limit = clamp_int(rate_limit, base_rate, 0, max_rate)
                                threads = clamp_int(threads, base_threads, 1, 50)
                                rate_limit, threads = apply_profile(profile, rate_limit, threads)
                                if tool == "nuclei" and int(base_rate or 0) > 0:
                                    # Respect explicit CLI/config tuning from baseline for agentic nuclei.
                                    rate_limit = int(base_rate)
                                proposed_wordlist = args.get("wordlist") if isinstance(args.get("wordlist"), str) else None
                                safe_wordlist = resolve_wordlist(proposed_wordlist) or resolve_wordlist(gobuster_wordlist)
                                browser_cfg_local = self._tool_config("browser_use")
                                try:
                                    browser_default_steps = int(browser_cfg_local.get("max_steps", 25))
                                except Exception:
                                    browser_default_steps = 25
                                browser_default_steps = max(1, min(browser_default_steps, 100))
                                planner_browser_task = str(args.get("task") or "").strip() or None
                                browser_model = str(args.get("model") or browser_cfg_local.get("model") or "").strip() or None
                                browser_command = str(browser_cfg_local.get("command") or "").strip() or None
                                browser_api_key = str(browser_cfg_local.get("api_key") or "").strip() or None
                                browser_api_key_env = str(browser_cfg_local.get("api_key_env") or "").strip()
                                if not browser_api_key and browser_api_key_env:
                                    browser_api_key = str(os.getenv(browser_api_key_env) or "").strip() or None
                                browser_session = (
                                    str(args.get("browser_session") or browser_cfg_local.get("session") or "").strip() or None
                                )
                                browser_auto_session = _as_bool(browser_cfg_local.get("auto_session"), True)
                                if tool == "browser_use" and not browser_session and browser_auto_session:
                                    browser_session = _auto_browser_session_name(target)
                                browser_profile = (
                                    str(args.get("browser_profile") or browser_cfg_local.get("profile") or "").strip() or None
                                )
                                browser_auth_ctx = _browser_use_auth_context(browser_cfg_local)
                                browser_allow_fallback = _as_bool(
                                    browser_cfg_local.get("allow_deterministic_fallback"), True
                                )
                                browser_deterministic_max_paths = clamp_int(
                                    browser_cfg_local.get("deterministic_max_paths"), 8, 1, 24
                                )
                                browser_task = planner_browser_task
                                if tool == "browser_use":
                                    browser_task = _build_browser_use_task(
                                        action,
                                        target_url=target,
                                        proposed_task=planner_browser_task,
                                        auth_ctx=browser_auth_ctx,
                                    )
                                browser_require_done = _as_bool(browser_cfg_local.get("require_done"), True)
                                browser_min_steps_success = clamp_int(
                                    browser_cfg_local.get("min_steps_success"), 1, 0, 100
                                )
                                raw_headless = args.get("headless", browser_cfg_local.get("headless", True))
                                if isinstance(raw_headless, str):
                                    browser_headless = raw_headless.strip().lower() in {"1", "true", "yes", "on"}
                                else:
                                    browser_headless = bool(raw_headless)
                                browser_steps = clamp_int(args.get("max_steps"), browser_default_steps, 1, 100)

                                if tool == "httpx":
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["httpx"].scan(
                                            [target],
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("httpx"),
                                        ),
                                    )
                                elif tool == "whatweb":
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["whatweb"].scan(
                                            target,
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("whatweb"),
                                        ),
                                    )
                                elif tool == "nuclei":
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["nuclei"].scan(
                                            target,
                                            rate_limit=rate_limit or None,
                                            tags=nuclei_tags,
                                            severity=nuclei_severity,
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("nuclei"),
                                        ),
                                    )
                                elif tool == "gobuster":
                                    if target in gobuster_wildcard_targets:
                                        entry = self._skip_tool(
                                            tool,
                                            "Wildcard/soft-404 behavior detected previously; pivoting to ffuf",
                                        )
                                    elif safe_wordlist:
                                        entry = self._run_tool(
                                            tool,
                                            lambda: self.scanners["gobuster"].scan(
                                                target,
                                                wordlist=safe_wordlist,
                                                threads=threads,
                                                cancel_event=cancel_event,
                                                timeout_seconds=self._tool_timeout_seconds("gobuster"),
                                            ),
                                        )
                                    else:
                                        entry = self._run_tool(
                                            tool,
                                            lambda: self.scanners["gobuster"].scan(
                                                target,
                                                threads=threads,
                                                cancel_event=cancel_event,
                                                timeout_seconds=self._tool_timeout_seconds("gobuster"),
                                            ),
                                        )
                                    wildcard_detected = _is_gobuster_wildcard_error(entry)
                                    if wildcard_detected:
                                        gobuster_wildcard_targets.add(target)
                                        entry["skipped"] = True
                                        entry["reason"] = "Wildcard/soft-404 behavior detected; pivoting to ffuf"
                                    if (
                                        not entry.get("success")
                                        and self._has_scanner("ffuf")
                                        and self._tool_enabled("ffuf", default=False)
                                    ):
                                        fallback_reason = "Fallback after gobuster failure"
                                        if "wildcard" in str(entry.get("reason") or "").lower():
                                            fallback_reason = "Fallback for wildcard/soft-404 gobuster target"
                                        ffuf_entry = self._run_tool(
                                            "ffuf",
                                            lambda: self.scanners["ffuf"].scan(
                                                target,
                                                wordlist=safe_wordlist,
                                                threads=max(10, int(threads)),
                                                cancel_event=cancel_event,
                                                timeout_seconds=self._tool_timeout_seconds("ffuf"),
                                            ),
                                        )
                                        ffuf_entry["phase"] = "agentic"
                                        ffuf_entry["target"] = target
                                        ffuf_entry["profile"] = profile
                                        ffuf_entry["fallback_for"] = "gobuster"
                                        ffuf_entry["reason"] = fallback_reason
                                        entry["_extra_results"] = [ffuf_entry]
                                        if ffuf_entry.get("success"):
                                            agentic_success.add(("ffuf", target))
                                elif tool == "ffuf":
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["ffuf"].scan(
                                            target,
                                            wordlist=safe_wordlist,
                                            threads=threads,
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("ffuf"),
                                        ),
                                    )
                                elif tool == "katana":
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["katana"].crawl(
                                            target,
                                            depth=int(self._tool_config("katana").get("depth", 3) or 3),
                                            concurrency=int(self._tool_config("katana").get("concurrency", 10) or 10),
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("katana"),
                                        ),
                                    )
                                elif tool == "browser_use":
                                    def _run_browser_use_with_config_key() -> Dict[str, Any]:
                                        key_to_export = str(browser_api_key or "").strip()
                                        prev_browser_use_api_key = os.environ.get("BROWSER_USE_API_KEY")
                                        set_browser_use_api_key = bool(key_to_export)
                                        if set_browser_use_api_key:
                                            os.environ["BROWSER_USE_API_KEY"] = key_to_export
                                        try:
                                            return self.scanners["browser_use"].scan(
                                                target,
                                                task=browser_task,
                                                max_steps=browser_steps,
                                                headless=browser_headless,
                                                model=browser_model,
                                                session=browser_session,
                                                profile=browser_profile,
                                                command=browser_command,
                                                require_done=browser_require_done,
                                                min_steps_success=browser_min_steps_success,
                                                allow_deterministic_fallback=browser_allow_fallback,
                                                deterministic_max_paths=browser_deterministic_max_paths,
                                                cancel_event=cancel_event,
                                                timeout_seconds=self._tool_timeout_seconds("browser_use"),
                                            )
                                        finally:
                                            if set_browser_use_api_key:
                                                if prev_browser_use_api_key is None:
                                                    os.environ.pop("BROWSER_USE_API_KEY", None)
                                                else:
                                                    os.environ["BROWSER_USE_API_KEY"] = prev_browser_use_api_key
                                    entry = self._run_tool(
                                        tool,
                                        _run_browser_use_with_config_key,
                                    )
                                elif tool == "nikto":
                                    try:
                                        u = urlparse(target)
                                        host = u.hostname or target
                                        port = int(u.port or (443 if (u.scheme or "").lower() == "https" else 80))
                                    except Exception:
                                        host = target
                                        port = 80
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["nikto"].scan(
                                            host,
                                            port=port,
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("nikto"),
                                        ),
                                    )
                                elif tool == "sqlmap":
                                    normalized_sql_target = self._normalize_sqlmap_candidate_url(target)
                                    if not normalized_sql_target:
                                        entry = self._skip_tool(tool, "No parameterized URL provided")
                                    else:
                                        target = normalized_sql_target
                                        args["target"] = target
                                        if target in sqlmap_rejected_targets:
                                            entry = self._skip_tool(
                                                tool,
                                                "SQLMap target previously marked non-viable in this run",
                                            )
                                        else:
                                            try:
                                                sqlmap_preflight_timeout = int(
                                                    sqlmap_cfg.get("preflight_timeout_seconds", 3)
                                                )
                                            except Exception:
                                                sqlmap_preflight_timeout = 3
                                            sqlmap_preflight_timeout = max(1, min(sqlmap_preflight_timeout, 15))
                                            preflight = self._sqlmap_preflight_viability(
                                                target,
                                                timeout_seconds=sqlmap_preflight_timeout,
                                            )
                                            if not bool(preflight.get("viable")):
                                                status_txt = str(preflight.get("status") or "").strip() or "unknown"
                                                entry = self._skip_tool(
                                                    tool,
                                                    f"Preflight blocked non-viable URL (HTTP {status_txt})",
                                                )
                                                entry["preflight"] = preflight
                                                sqlmap_rejected_targets.add(target)
                                            else:
                                                entry = self._run_tool(
                                                    tool,
                                                    lambda: self.scanners["sqlmap"].scan(
                                                        target,
                                                        cancel_event=cancel_event,
                                                        timeout_seconds=self._tool_timeout_seconds("sqlmap"),
                                                    ),
                                                )
                                                entry["preflight"] = preflight
                                                temp_entry = dict(entry) if isinstance(entry, dict) else {}
                                                temp_entry["target"] = target
                                                if self._sqlmap_entry_indicates_nonviable(temp_entry):
                                                    sqlmap_rejected_targets.add(target)
                                else:
                                    entry = self._skip_tool(tool, "Unsupported agentic action")
                    elif tool == "dnsenum":
                        action_target = scan_host
                        action_key = (tool, action_target or "")
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif not self._should_run_dnsenum(scan_host):
                            entry = self._skip_tool(tool, self._dns_target_skip_reason(scan_host))
                        else:
                            entry = self._run_tool(
                                tool,
                                lambda: self.scanners["dnsenum"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("dnsenum"),
                                ),
                            )
                    elif tool == "subfinder":
                        action_target = scan_host
                        action_key = (tool, action_target or "")
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif not self._should_run_dnsenum(scan_host):
                            entry = self._skip_tool(tool, self._dns_target_skip_reason(scan_host))
                        else:
                            entry = self._run_tool(
                                tool,
                                lambda: self.scanners["subfinder"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("subfinder"),
                                ),
                            )
                    elif tool == "sslscan":
                        port = _resolve_sslscan_port_for_action(action)
                        action_target = scan_host
                        action_port = port
                        action_key = (tool, action_target or "", str(action_port or ""))
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif port is None:
                            entry = self._skip_tool(tool, "No eligible TLS candidate port for action")
                        else:
                            entry = self._run_tool(
                                tool,
                                lambda: self.scanners["sslscan"].scan(
                                    scan_host,
                                    port=port,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("sslscan"),
                                ),
                            )
                            if isinstance(entry, dict):
                                entry["port"] = int(port)
                    elif tool == "enum4linux-ng":
                        action_target = scan_host
                        action_key = (tool, action_target or "")
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif not smb_ports:
                            entry = self._skip_tool(tool, "No SMB ports detected (139/445)")
                        else:
                            entry = self._run_tool(
                                tool,
                                lambda: self.scanners["enum4linux-ng"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("enum4linux-ng"),
                                ),
                            )
                    elif tool == "trivy":
                        action_target = container_image
                        action_key = (tool, action_target or "")
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif not container_image:
                            entry = self._skip_tool(tool, "No container image provided")
                        else:
                            entry = self._run_tool(
                                tool,
                                lambda: self.scanners["trivy"].scan(
                                    container_image,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("trivy"),
                                ),
                            )
                    else:
                        entry = self._skip_tool(tool, "Unsupported agentic action")

                    entry["phase"] = "agentic"
                    if tool == "sslscan":
                        if action_port is not None:
                            entry["target"] = f"{scan_host}:{int(action_port)}"
                        elif scan_host:
                            entry["target"] = scan_host
                    elif target:
                        entry["target"] = target
                    entry["profile"] = profile
                    if entry.get("success") and not entry.get("skipped"):
                        if tool_specs.get(tool, {}).get("target_kind") == "web":
                            agentic_success.add((tool, action_target or ""))
                        elif tool in ("dnsenum", "subfinder", "enum4linux-ng"):
                            agentic_success.add((tool, scan_host or ""))
                        elif tool == "sslscan":
                            agentic_success.add((tool, scan_host or "", str(action_port or "")))
                        elif tool == "trivy":
                            agentic_success.add((tool, container_image or ""))
                    return entry

                agentic_success: set[tuple] = set()
                actions_executed = 0
                low_signal_streak = 0
                nonpositive_after_broad_streak = 0
                agentic_tool_counts: Dict[str, int] = {}
                agentic_target_counts: Dict[str, int] = {}
                agentic_action_counts: Dict[Tuple[str, str], int] = {}
                agentic_low_signal_tool_counts: Dict[str, int] = {}
                agentic_tool_risk_gain_counts: Dict[str, int] = {}
                agentic_tool_no_risk_gain_counts: Dict[str, int] = {}
                agentic_tool_gain_scores: Dict[str, List[int]] = {}
                recent_gain_scores: List[int] = []
                planner_action_ledger: List[Dict[str, Any]] = []
                planner_blocked_candidates: List[Dict[str, Any]] = []
                coverage_debt_pivot_count = 0
                coverage_debt_pivot_cap = 2
                gobuster_wildcard_targets: Set[str] = set()
                browser_use_fallback_block_targets: Set[str] = set()

                for baseline_entry in agg.get("results", []) or []:
                    if not isinstance(baseline_entry, dict):
                        continue
                    if str(baseline_entry.get("tool") or "").strip().lower() != "gobuster":
                        continue
                    baseline_target = str(baseline_entry.get("target") or "").strip()
                    if not baseline_target:
                        continue
                    if not _is_gobuster_wildcard_error(baseline_entry):
                        continue
                    normalized_target = _canonicalize_web_action_target("gobuster", baseline_target)
                    resolved_target = _resolve_allowed_web_target("gobuster", normalized_target)
                    gobuster_wildcard_targets.add(resolved_target or normalized_target)

                def _target_on_allowed_web_surface(target: str) -> bool:
                    text = str(target or "").strip()
                    if not text:
                        return False
                    try:
                        parsed = urlparse(text)
                        if not parsed.scheme:
                            return False
                        host = str(parsed.hostname or "").strip().lower()
                        if not host:
                            return False
                        port = int(parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80))
                    except Exception:
                        return False
                    for item in allowed_web_targets or []:
                        item_text = str(item or "").strip()
                        if not item_text:
                            continue
                        try:
                            item_parsed = urlparse(item_text)
                            if not item_parsed.scheme:
                                continue
                            item_host = str(item_parsed.hostname or "").strip().lower()
                            if not item_host:
                                continue
                            item_port = int(item_parsed.port or (443 if (item_parsed.scheme or "").lower() == "https" else 80))
                        except Exception:
                            continue
                        if item_host == host and item_port == port:
                            return True
                    return False

                def _baseline_would_skip(action: Dict[str, Any]) -> bool:
                    tool = action.get("tool")
                    spec = tool_specs.get(tool, {})
                    if spec.get("target_kind") != "web":
                        return False
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    target = args.get("target") if isinstance(args.get("target"), str) else None
                    if not target:
                        return True
                    resolved_target = _resolve_allowed_web_target(str(tool or "").strip().lower(), target)
                    if resolved_target is None:
                        return True
                    if str(tool or "").strip().lower() != "sqlmap":
                        target = resolved_target
                    return (tool, target) in baseline_success or (tool, target) in agentic_success

                def _covered_action_exclusions(extra_actions: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
                    """
                    Build a broad exclusion list so a replan avoids already-covered actions
                    (baseline + earlier agentic executions), not just the immediate top candidate.
                    """
                    out: List[Dict[str, Any]] = []
                    seen: Set[Tuple[str, str, str, str]] = set()
                    default_profile = requested_compliance or "standard"

                    def _add(
                        tool: str,
                        target: str,
                        profile: str = default_profile,
                        port: Optional[Any] = None,
                    ) -> None:
                        t = str(tool or "").strip().lower()
                        u = str(target or "").strip()
                        p = str(profile or default_profile).strip().lower() or default_profile
                        port_txt = str(port).strip() if port is not None else ""
                        if not t or not u:
                            return
                        key = (t, u, p, port_txt)
                        if key in seen:
                            return
                        seen.add(key)
                        args: Dict[str, Any] = {"profile": p, "target": u}
                        if port_txt:
                            try:
                                args["port"] = int(port_txt)
                            except Exception:
                                args["port"] = port_txt
                        out.append(
                            {
                                "tool": t,
                                "arguments": args,
                                "profile": p,
                                "priority": 50,
                                "reasoning": "",
                                "hypothesis": "",
                                "expected_evidence": "",
                            }
                        )

                    for item in sorted(baseline_success | agentic_success):
                        if not isinstance(item, tuple) or len(item) < 2:
                            continue
                        maybe_port = item[2] if len(item) >= 3 and str(item[0]).strip().lower() == "sslscan" else None
                        _add(str(item[0]), str(item[1]), port=maybe_port)

                    high_risk_targets = _high_risk_web_targets_now()
                    for target in sorted(baseline_broad_nuclei_targets):
                        if high_risk_targets and target in high_risk_targets:
                            continue
                        _add("nuclei", str(target))

                    for action in extra_actions or []:
                        if not isinstance(action, dict):
                            continue
                        args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                        _add(
                            str(action.get("tool") or ""),
                            str(args.get("target") or ""),
                            str(action.get("profile") or default_profile),
                            args.get("port"),
                        )
                    return out

                def _action_trace_view(action: Dict[str, Any]) -> Dict[str, Any]:
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    tool = str(action.get("tool") or "").strip().lower()
                    port_value = args.get("port")
                    if tool == "sslscan" and port_value is None:
                        resolved_port = _resolve_sslscan_port_for_action(action)
                        if resolved_port is not None:
                            port_value = int(resolved_port)
                    return {
                        "tool": action.get("tool"),
                        "target": args.get("target"),
                        "port": port_value,
                        "profile": action.get("profile"),
                        "priority": action.get("priority"),
                        "reasoning": action.get("reasoning"),
                        "hypothesis": action.get("hypothesis"),
                        "expected_evidence": action.get("expected_evidence"),
                    }

                def _findings_state_now() -> Dict[str, Any]:
                    try:
                        items = self._collect_findings(agg)
                    except Exception:
                        items = []
                    if not isinstance(items, list):
                        items = []
                    all_keys: Set[str] = set()
                    baseline_keys: Set[str] = set()
                    agentic_keys: Set[str] = set()
                    baseline_total = 0
                    agentic_total = 0
                    risk_classes = self._risk_classes_from_findings(items)
                    for finding in items:
                        if not isinstance(finding, dict):
                            continue
                        dedup_key = str(finding.get("dedup_key") or "").strip()
                        if not dedup_key:
                            dedup_key = self._finding_dedup_key(finding)
                        if dedup_key:
                            all_keys.add(dedup_key)
                        phase = str(finding.get("phase") or "baseline").strip().lower() or "baseline"
                        if phase == "agentic":
                            agentic_total += 1
                            if dedup_key:
                                agentic_keys.add(dedup_key)
                        else:
                            baseline_total += 1
                            if dedup_key:
                                baseline_keys.add(dedup_key)
                    cluster_state = _cluster_findings_for_planner(items)
                    return {
                        "items": items,
                        "total_count": len(items),
                        "unique_all_count": len(all_keys),
                        "risk_classes": risk_classes,
                        "all_keys": all_keys,
                        "baseline_total": int(baseline_total),
                        "agentic_total": int(agentic_total),
                        "baseline_keys": baseline_keys,
                        "agentic_keys": agentic_keys,
                        "open_high_risk_clusters": cluster_state.get("open_high_risk_clusters", []),
                        "open_high_risk_cluster_count": len(cluster_state.get("open_high_risk_clusters", []) or []),
                    }

                def _target_host_port_key(value: str) -> Optional[Tuple[str, int]]:
                    text = str(value or "").strip()
                    if not text:
                        return None
                    try:
                        parsed = urlparse(text)
                        if not parsed.scheme:
                            return None
                        host = str(parsed.hostname or "").strip().lower()
                        if host in {"localhost", "::1"}:
                            host = "127.0.0.1"
                        if not host:
                            return None
                        port = int(parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80))
                        return (host, port)
                    except Exception:
                        return None

                def _target_risk_scores_now() -> Dict[str, int]:
                    scores: Dict[str, int] = {}
                    by_host_port: Dict[Tuple[str, int], List[str]] = {}
                    by_host: Dict[str, List[str]] = {}
                    for item in allowed_web_targets or []:
                        target = str(item or "").strip()
                        if not target:
                            continue
                        scores[target] = 0
                        host_port = _target_host_port_key(target)
                        if host_port:
                            by_host_port.setdefault(host_port, []).append(target)
                            by_host.setdefault(host_port[0], []).append(target)

                    findings = self._collect_findings(agg)
                    if not isinstance(findings, list) or not scores:
                        return scores

                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        rank = int(self._severity_rank(finding.get("severity") or "INFO"))
                        if rank <= 0:
                            continue
                        risk_class = str(finding.get("risk_class") or "").strip().lower()
                        class_bonus = 2 if risk_class in ("secret_exposure", "known_vulnerability", "data_plane_exposure") else 1
                        weight = max(1, rank) * class_bonus
                        matched_targets: Set[str] = set()

                        text = " ".join(
                            [
                                str(finding.get("title") or "").strip(),
                                str(finding.get("evidence") or "").strip(),
                                str(finding.get("target") or "").strip(),
                            ]
                        ).strip()
                        for url in re.findall(r"https?://[^\s)>'\"`]+", text, flags=re.IGNORECASE):
                            host_port = _target_host_port_key(str(url).rstrip(".,;"))
                            if host_port:
                                for mapped in by_host_port.get(host_port, []):
                                    matched_targets.add(mapped)

                        if not matched_targets:
                            host, _ = self._extract_finding_host_path(finding)
                            host = str(host or "").strip().lower()
                            if host:
                                for mapped in by_host.get(host, []):
                                    matched_targets.add(mapped)

                        for target in matched_targets:
                            scores[target] = int(scores.get(target, 0)) + int(weight)

                    return scores

                def _target_max_severity_ranks_now() -> Dict[str, int]:
                    scores: Dict[str, int] = {}
                    by_host_port: Dict[Tuple[str, int], List[str]] = {}
                    by_host: Dict[str, List[str]] = {}
                    for item in allowed_web_targets or []:
                        target = str(item or "").strip()
                        if not target:
                            continue
                        scores[target] = 0
                        host_port = _target_host_port_key(target)
                        if host_port:
                            by_host_port.setdefault(host_port, []).append(target)
                            by_host.setdefault(host_port[0], []).append(target)

                    findings = self._collect_findings(agg)
                    if not isinstance(findings, list) or not scores:
                        return scores

                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        rank = int(self._severity_rank(finding.get("severity") or "INFO"))
                        if rank <= 0:
                            continue
                        matched_targets: Set[str] = set()
                        text = " ".join(
                            [
                                str(finding.get("title") or "").strip(),
                                str(finding.get("evidence") or "").strip(),
                                str(finding.get("target") or "").strip(),
                            ]
                        ).strip()
                        for url in re.findall(r"https?://[^\s)>'\"`]+", text, flags=re.IGNORECASE):
                            host_port = _target_host_port_key(str(url).rstrip(".,;"))
                            if host_port:
                                for mapped in by_host_port.get(host_port, []):
                                    matched_targets.add(mapped)
                        if not matched_targets:
                            host, _ = self._extract_finding_host_path(finding)
                            host = str(host or "").strip().lower()
                            if host:
                                for mapped in by_host.get(host, []):
                                    matched_targets.add(mapped)
                        for target in matched_targets:
                            scores[target] = max(int(scores.get(target, 0)), int(rank))

                    return scores

                def _high_risk_web_targets_now() -> Set[str]:
                    scores = _target_risk_scores_now()
                    ranked = [(int(score), target) for target, score in scores.items() if int(score) > 0]
                    if not ranked:
                        return set()
                    ranked.sort(key=lambda item: (-item[0], item[1]))
                    cap = max(1, min(4, max(1, len(allowed_web_targets) // 3)))
                    return {target for _, target in ranked[:cap]}

                def _open_high_risk_clusters_now() -> List[Dict[str, Any]]:
                    try:
                        state = _findings_state_now()
                        rows = state.get("open_high_risk_clusters", [])
                        if isinstance(rows, list):
                            return [r for r in rows if isinstance(r, dict)]
                    except Exception:
                        pass
                    return []

                def _open_high_risk_target_hints_now() -> Dict[str, Set[str]]:
                    hosts: Set[str] = set()
                    host_ports: Set[str] = set()
                    try:
                        open_clusters = _open_high_risk_clusters_now()
                    except Exception:
                        open_clusters = []
                    if not isinstance(open_clusters, list):
                        return {"hosts": hosts, "host_ports": host_ports}
                    for cluster in open_clusters:
                        if not isinstance(cluster, dict):
                            continue
                        for target_label in cluster.get("targets", []) or []:
                            text = str(target_label or "").strip()
                            if not text:
                                continue
                            try:
                                if "://" in text:
                                    parsed = urlparse(text)
                                    host = str(parsed.hostname or "").strip().lower()
                                    if host in {"localhost", "::1"}:
                                        host = "127.0.0.1"
                                    if host:
                                        hosts.add(host)
                                    port_val = parsed.port
                                    if host and port_val is not None:
                                        host_ports.add(f"{host}:{int(port_val)}")
                                    continue
                            except Exception:
                                pass
                            host_part = str(text).split("/", 1)[0].strip().lower().strip("[]")
                            if not host_part:
                                continue
                            if ":" in host_part:
                                maybe_host, maybe_port = host_part.rsplit(":", 1)
                                if maybe_host:
                                    if maybe_host in {"localhost", "::1"}:
                                        maybe_host = "127.0.0.1"
                                    hosts.add(maybe_host)
                                    try:
                                        host_ports.add(f"{maybe_host}:{int(maybe_port)}")
                                        continue
                                    except Exception:
                                        pass
                            if host_part in {"localhost", "::1"}:
                                host_part = "127.0.0.1"
                            hosts.add(host_part)
                    return {"hosts": hosts, "host_ports": host_ports}

                def _action_links_open_high_risk_cluster(action: Dict[str, Any]) -> bool:
                    if not isinstance(action, dict):
                        return False
                    hints = _open_high_risk_target_hints_now()
                    hosts = hints.get("hosts", set()) if isinstance(hints, dict) else set()
                    host_ports = hints.get("host_ports", set()) if isinstance(hints, dict) else set()
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    tool = str(action.get("tool") or "").strip().lower()
                    target = str(args.get("target") or "").strip()
                    if target:
                        host_port = _target_host_port_key(target)
                        if host_port:
                            host = str(host_port[0]).strip().lower()
                            pair = f"{host}:{int(host_port[1])}"
                            if pair in host_ports:
                                return True
                            if not host_ports and host in hosts:
                                return True
                        else:
                            host_only = str(target).split("/", 1)[0].strip().lower().strip("[]")
                            if host_only in {"localhost", "::1"}:
                                host_only = "127.0.0.1"
                            if host_only in hosts:
                                return True
                    if tool == "sslscan":
                        resolved_port = _resolve_sslscan_port_for_action(action)
                        host = str(scan_host or "").strip().lower().strip("[]")
                        if host and host in hosts:
                            return True
                        if host and resolved_port is not None and f"{host}:{int(resolved_port)}" in host_ports:
                            return True
                    if target and not host_ports and target in _high_risk_web_targets_now():
                        return True
                    return False

                def _coverage_debt_pivot_tool_order(open_clusters: List[Dict[str, Any]]) -> List[str]:
                    risk_counts: Dict[str, int] = {}
                    for cluster in open_clusters or []:
                        if not isinstance(cluster, dict):
                            continue
                        rc = str(cluster.get("risk_class") or "general_security_signal").strip().lower()
                        if not rc:
                            rc = "general_security_signal"
                        risk_counts[rc] = int(risk_counts.get(rc, 0)) + 1

                    if not risk_counts:
                        preferred = ["httpx", "browser_use", "nuclei", "whatweb", "gobuster", "ffuf", "katana"]
                    elif "secret_exposure" in risk_counts:
                        preferred = ["httpx", "browser_use", "whatweb", "nuclei", "gobuster", "ffuf", "katana"]
                    elif any(
                        k in risk_counts
                        for k in ("unauthenticated_exposure", "data_plane_exposure", "general_security_signal")
                    ):
                        preferred = ["httpx", "browser_use", "nuclei", "whatweb", "gobuster", "ffuf", "katana"]
                    else:
                        preferred = ["httpx", "browser_use", "nuclei", "whatweb", "gobuster", "ffuf", "katana"]
                    return [t for t in preferred if t in allowed_tools]

                def _coverage_debt_candidate_targets(
                    open_clusters: List[Dict[str, Any]],
                    repeat_blocked_actions: List[Dict[str, Any]],
                ) -> List[str]:
                    by_host: Dict[str, List[str]] = {}
                    by_host_port: Dict[Tuple[str, int], List[str]] = {}
                    for item in allowed_web_targets or []:
                        target = str(item or "").strip()
                        if not target:
                            continue
                        hp = _target_host_port_key(target)
                        if not hp:
                            continue
                        by_host.setdefault(hp[0], []).append(target)
                        by_host_port.setdefault(hp, []).append(target)

                    out: List[str] = []
                    seen: Set[str] = set()

                    def _add(url: str) -> None:
                        u = str(url or "").strip()
                        if not u or u in seen:
                            return
                        seen.add(u)
                        out.append(u)

                    def _add_allowed_surface_url(value: Any) -> None:
                        preserved = _preserve_allowed_web_target_path(str(value or "").strip())
                        if preserved:
                            _add(preserved)

                    # 1) Prefer concrete URLs from unresolved cluster evidence.
                    for cluster in open_clusters[:10]:
                        if not isinstance(cluster, dict):
                            continue
                        for sample in cluster.get("evidence_samples", []) or []:
                            text = str(sample or "").strip()
                            if not text:
                                continue
                            for url in re.findall(r"https?://[^\s)>'\"`]+", text, flags=re.IGNORECASE):
                                _add_allowed_surface_url(str(url).rstrip(".,;"))

                    # 2) Prefer blocked nuclei targets (same host:port surface).
                    for cand in repeat_blocked_actions or []:
                        if not isinstance(cand, dict):
                            continue
                        if str(cand.get("tool") or "").strip().lower() != "nuclei":
                            continue
                        args = cand.get("arguments") if isinstance(cand.get("arguments"), dict) else {}
                        target = str(args.get("target") or "").strip()
                        hp = _target_host_port_key(target)
                        if hp:
                            for mapped in by_host_port.get(hp, []):
                                _add(mapped)

                    # 3) Cluster labels -> host/path candidates on in-scope host:port surfaces.
                    for cluster in open_clusters[:10]:
                        if not isinstance(cluster, dict):
                            continue
                        for target_label in cluster.get("targets", []) or []:
                            text = str(target_label or "").strip()
                            if not text:
                                continue
                            host_part = text
                            path_part = ""
                            if "/" in text:
                                host_part, remainder = text.split("/", 1)
                                path_part = "/" + remainder.lstrip("/")
                            host_part = host_part.strip().lower().strip("[]")
                            if not host_part:
                                continue
                            mapped_bases: List[str] = []
                            if ":" in host_part:
                                maybe_host, maybe_port = host_part.rsplit(":", 1)
                                try:
                                    hp = (str(maybe_host).strip().lower(), int(maybe_port))
                                    mapped_bases = by_host_port.get(hp, [])
                                except Exception:
                                    mapped_bases = []
                            else:
                                mapped_bases = by_host.get(host_part, [])
                            for base in mapped_bases:
                                if path_part and path_part != "/":
                                    _add_allowed_surface_url(f"{str(base).rstrip('/')}{path_part}")
                                else:
                                    _add_allowed_surface_url(base if str(base).endswith("/") else f"{str(base).rstrip('/')}/")
                                _add(base)

                    # 4) High-risk web targets from current evidence graph.
                    unresolved_hints = _open_high_risk_target_hints_now()
                    unresolved_hosts = unresolved_hints.get("hosts", set()) if isinstance(unresolved_hints, dict) else set()
                    unresolved_host_ports = (
                        unresolved_hints.get("host_ports", set()) if isinstance(unresolved_hints, dict) else set()
                    )

                    def _target_matches_unresolved_surface(value: str) -> bool:
                        text = str(value or "").strip()
                        if not text:
                            return False
                        hp = _target_host_port_key(text)
                        if hp:
                            host = str(hp[0]).strip().lower()
                            pair = f"{host}:{int(hp[1])}"
                            if pair in unresolved_host_ports:
                                return True
                            if not unresolved_host_ports and host in unresolved_hosts:
                                return True
                            return False
                        host_only = str(text).split("/", 1)[0].strip().lower().strip("[]")
                        if host_only in {"localhost", "::1"}:
                            host_only = "127.0.0.1"
                        return bool(host_only) and host_only in unresolved_hosts and not unresolved_host_ports

                    risk_scores = _target_risk_scores_now()
                    ranked_risk_targets = [
                        t for _, t in sorted([(int(v), k) for k, v in risk_scores.items() if int(v) > 0], key=lambda x: (-x[0], x[1]))
                    ]
                    for target in ranked_risk_targets[:8]:
                        if _target_matches_unresolved_surface(target):
                            _add(target)

                    if not out:
                        for target in allowed_web_targets[:6]:
                            if _target_matches_unresolved_surface(target):
                                _add(target)
                    return out[:12]

                def _build_coverage_debt_pivot_actions(
                    open_clusters: List[Dict[str, Any]],
                    repeat_blocked_actions: List[Dict[str, Any]],
                    repeat_blocked_reason_map: Dict[Tuple[str, str], str],
                ) -> List[Dict[str, Any]]:
                    if int(coverage_debt_pivot_count) >= int(coverage_debt_pivot_cap):
                        return []
                    tool_order = _coverage_debt_pivot_tool_order(open_clusters)
                    if not tool_order:
                        return []
                    targets = _coverage_debt_candidate_targets(open_clusters, repeat_blocked_actions)
                    if not targets:
                        return []

                    profile = requested_compliance or "standard"
                    reason_by_tool = {
                        "httpx": (
                            "Coverage-debt pivot: revalidate the unresolved high-risk endpoint directly and "
                            "capture concrete status/title/header evidence on the specific path."
                        ),
                        "browser_use": (
                            "Coverage-debt pivot: validate unresolved high-risk exposure through an "
                            "interactive web workflow and capture audit-grade endpoint evidence."
                        ),
                        "nuclei": (
                            "Coverage-debt pivot: run targeted template validation against the unresolved "
                            "high-risk endpoint for reproducible proof."
                        ),
                        "whatweb": (
                            "Coverage-debt pivot: fingerprint unresolved high-risk service to confirm "
                            "component/header context before remediation."
                        ),
                        "gobuster": (
                            "Coverage-debt pivot: enumerate unlinked high-risk paths tied to unresolved "
                            "exposure clusters."
                        ),
                        "ffuf": (
                            "Coverage-debt pivot: perform focused content discovery to validate unresolved "
                            "high-risk exposure hypotheses."
                        ),
                        "katana": (
                            "Coverage-debt pivot: crawl unresolved high-risk web surface to discover "
                            "linked endpoints for follow-up validation."
                        ),
                    }
                    expected_by_tool = {
                        "httpx": "HTTP status/title/header evidence for the unresolved high-risk endpoint.",
                        "browser_use": "Rendered workflow observations and concrete endpoint artifacts tied to unresolved exposure.",
                        "nuclei": "Template-level evidence confirming or disproving the unresolved high-risk hypothesis.",
                        "whatweb": "Service fingerprint and security-relevant headers linked to unresolved clusters.",
                        "gobuster": "Additional high-value paths/endpoints supporting or disproving unresolved cluster impact.",
                        "ffuf": "HTTP hits on sensitive/admin/config paths relevant to unresolved high-risk findings.",
                        "katana": "Discovered endpoint graph and candidate URLs associated with unresolved high-risk areas.",
                    }
                    priority_by_tool = {
                        "httpx": 1,
                        "browser_use": 2,
                        "nuclei": 3,
                        "whatweb": 5,
                        "gobuster": 6,
                        "ffuf": 7,
                        "katana": 8,
                    }

                    out: List[Dict[str, Any]] = []
                    seen_keys: Set[Tuple[str, str]] = set()
                    for target in targets:
                        for tool in tool_order:
                            action = {
                                "tool": tool,
                                "arguments": {"profile": profile, "target": str(target).strip()},
                                "profile": profile,
                                "reasoning": reason_by_tool.get(tool, "Coverage-debt pivot action."),
                                "hypothesis": (
                                    "This in-scope target contains additional evidence to close unresolved "
                                    "high-risk clusters."
                                ),
                                "expected_evidence": expected_by_tool.get(tool, "Additional evidence for unresolved clusters."),
                                "priority": int(priority_by_tool.get(tool, 5)),
                            }
                            key = _action_repeat_key(action)
                            if key and key in seen_keys:
                                continue
                            if _baseline_would_skip(action):
                                continue
                            block_reason = _repeat_block_reason(action)
                            if block_reason:
                                continue
                            if not _action_links_open_high_risk_cluster(action):
                                continue
                            if key:
                                seen_keys.add(key)
                            out.append(action)
                            if len(out) >= 4:
                                return out
                    return out

                def _normalize_target_label(value: Any) -> str:
                    text = str(value or "").strip()
                    if not text:
                        return ""
                    try:
                        parsed = urlparse(text)
                        if parsed.scheme:
                            host = str(parsed.hostname or "").strip().lower()
                            if not host:
                                return text.lower()
                            port = int(parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80))
                            return f"{host}:{port}"
                    except Exception:
                        pass
                    return text.lower()

                def _baseline_action_ledger() -> List[Dict[str, Any]]:
                    rows: List[Dict[str, Any]] = []
                    for entry in agg.get("results", []) or []:
                        if not isinstance(entry, dict):
                            continue
                        if str(entry.get("phase") or "baseline").strip().lower() != "baseline":
                            continue
                        status = "skipped" if entry.get("skipped") else ("success" if entry.get("success") else "failed")
                        rows.append(
                            {
                                "phase": "baseline",
                                "tool": str(entry.get("tool") or "").strip(),
                                "target": str(entry.get("target") or "").strip(),
                                "status": status,
                                "reason": str(entry.get("reason") or "").strip(),
                                "error": str(entry.get("error") or "").strip(),
                            }
                        )
                    return rows

                def _cluster_findings_for_planner(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
                    by_key: Dict[str, Dict[str, Any]] = {}
                    agentic_risk_host_ports: Dict[str, Set[str]] = {}
                    agentic_risk_hosts: Dict[str, Set[str]] = {}
                    agentic_risk_target_paths: Dict[str, Set[str]] = {}
                    total = 0

                    def _host_port_keys_from_labels(labels: List[str]) -> Set[str]:
                        out: Set[str] = set()

                        def _normalize_host(value: str) -> str:
                            host_text = str(value or "").strip().lower().strip("[]")
                            if host_text in {"localhost", "::1"}:
                                return "127.0.0.1"
                            return host_text

                        for raw in labels or []:
                            text = str(raw or "").strip().rstrip(".,;")
                            if not text:
                                continue
                            try:
                                parsed = urlparse(text)
                                if parsed.scheme:
                                    host = _normalize_host(parsed.hostname or "")
                                    if host:
                                        port = int(parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80))
                                        out.add(f"{host}:{port}")
                                    continue
                            except Exception:
                                pass
                            host_part = _normalize_host(str(text).split("/", 1)[0])
                            if ":" not in host_part:
                                continue
                            host_txt, port_txt = host_part.rsplit(":", 1)
                            if not host_txt:
                                continue
                            try:
                                out.add(f"{host_txt}:{int(port_txt)}")
                            except Exception:
                                continue
                        return out

                    def _host_keys_from_labels(labels: List[str]) -> Set[str]:
                        out: Set[str] = set()
                        for raw in labels or []:
                            text = str(raw or "").strip().rstrip(".,;")
                            if not text:
                                continue
                            try:
                                parsed = urlparse(text)
                                if parsed.scheme:
                                    host = str(parsed.hostname or "").strip().lower().strip("[]")
                                    if host in {"localhost", "::1"}:
                                        host = "127.0.0.1"
                                    if host:
                                        out.add(host)
                                    continue
                            except Exception:
                                pass
                            host_part = str(text).split("/", 1)[0].strip().lower().strip("[]")
                            if not host_part:
                                continue
                            if ":" in host_part:
                                host_part = host_part.rsplit(":", 1)[0].strip()
                            if host_part in {"localhost", "::1"}:
                                host_part = "127.0.0.1"
                            if host_part:
                                out.add(host_part)
                        return out

                    def _target_path_keys_from_labels(labels: List[str]) -> Set[str]:
                        out: Set[str] = set()

                        def _normalize_host(value: str) -> str:
                            host_text = str(value or "").strip().lower().strip("[]")
                            if host_text in {"localhost", "::1"}:
                                return "127.0.0.1"
                            return host_text

                        def _normalize_path(value: str) -> str:
                            path_text = str(value or "/").strip() or "/"
                            if "?" in path_text:
                                path_part, query_part = path_text.split("?", 1)
                                path_part = path_part.rstrip("/") or "/"
                                return f"{path_part}?{query_part}"
                            return path_text.rstrip("/") or "/"

                        for raw in labels or []:
                            text = str(raw or "").strip().rstrip(".,;")
                            if not text:
                                continue
                            try:
                                parsed = urlparse(text)
                                if parsed.scheme:
                                    host = _normalize_host(parsed.hostname or "")
                                    if not host:
                                        continue
                                    port = int(parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80))
                                    path = _normalize_path(
                                        f"{str(parsed.path or '/').strip() or '/'}"
                                        + (f"?{parsed.query}" if parsed.query else "")
                                    )
                                    out.add(f"{host}:{port}{path}")
                                    continue
                            except Exception:
                                pass
                            if "/" not in text:
                                continue
                            host_part, remainder = text.split("/", 1)
                            host_raw = str(host_part or "").strip()
                            if not host_raw:
                                continue
                            host = _normalize_host(host_raw)
                            if not host:
                                continue
                            origin = host
                            if ":" in host_raw:
                                maybe_host, maybe_port = host_raw.rsplit(":", 1)
                                maybe_host = _normalize_host(maybe_host)
                                if maybe_host:
                                    try:
                                        origin = f"{maybe_host}:{int(maybe_port)}"
                                    except Exception:
                                        origin = maybe_host
                            out.add(f"{origin}{_normalize_path('/' + remainder.lstrip('/'))}")
                        return out

                    def _surface_label_from_finding(finding: Dict[str, Any]) -> Tuple[str, str]:
                        labels: List[str] = []
                        target_hint = str(finding.get("target") or "").strip()
                        if target_hint:
                            labels.append(target_hint)
                        title = str(finding.get("title") or "").strip()
                        evidence = str(finding.get("evidence") or "").strip()
                        for blob in (title, evidence):
                            if not blob:
                                continue
                            labels.extend(
                                str(u).rstrip(".,;")
                                for u in re.findall(r"https?://[^\s)>'\"`]+", blob, flags=re.IGNORECASE)
                            )

                        target_paths = sorted(_target_path_keys_from_labels(labels))
                        if target_paths:
                            surface = target_paths[0]
                            if "/" in surface:
                                origin, _, rest = surface.partition("/")
                                return origin, f"/{rest.lstrip('/')}" if rest else "/"
                            return surface, "/"

                        host_ports = sorted(_host_port_keys_from_labels(labels))
                        if host_ports:
                            return host_ports[0], "/"

                        host, path = self._extract_finding_host_path(finding)
                        host = str(host or "").strip().lower()
                        return host, str(path or "/").strip() or "/"

                    def _risk_match_classes(
                        risk_class: str,
                        title_text: str,
                        evidence_text: str,
                    ) -> Set[str]:
                        classes: Set[str] = set()
                        rc = str(risk_class or "").strip().lower()
                        if rc:
                            classes.add(rc)
                        joined = f"{str(title_text or '')} {str(evidence_text or '')}".strip().lower()
                        if any(k in joined for k in ("service role key", "secret", "token", "password", "credential", "api key")):
                            classes.add("secret_exposure")
                        if any(k in joined for k in ("sql injection", "xss", "rce", "cve", "vulnerability", "auth bypass")):
                            classes.add("known_vulnerability")
                        if any(
                            k in joined
                            for k in (
                                "without authentication",
                                "unauthenticated",
                                "anonymous",
                                "publicly accessible",
                                "exposed",
                                "open port",
                            )
                        ):
                            classes.add("unauthenticated_exposure")
                        if any(k in joined for k in ("tls", "ssl", "cipher", "certificate", "cleartext", "https")):
                            classes.add("transport_security")
                        if any(k in joined for k in ("redis", "postgres", "database", "rest api", "rpc", "rls")):
                            classes.add("data_plane_exposure")
                        if any(k in joined for k in ("missing security headers", "misconfig", "configuration", "default")):
                            classes.add("security_misconfiguration")
                        if "known_vulnerability" in classes:
                            classes.add("vulnerability_signal")
                        if "vulnerability_signal" in classes:
                            classes.add("known_vulnerability")
                        if not classes:
                            classes.add("general_security_signal")
                        return classes

                    def _planner_cluster_key(
                        dedup_key: str,
                        severity: str,
                        severity_rank: int,
                        risk_class: str,
                        title: str,
                        evidence: str,
                        origin: str,
                        path: str,
                    ) -> str:
                        # Planner clusters should be coarser than raw finding dedup keys so
                        # one endpoint-level high-risk exposure does not inflate into multiple
                        # open coverage-debt clusters across complementary tools.
                        if severity_rank < 4 or not origin or not path:
                            return dedup_key
                        candidate_risk_classes = _risk_match_classes(risk_class, title, evidence)
                        canonical_order = (
                            "secret_exposure",
                            "data_plane_exposure",
                            "unauthenticated_exposure",
                            "security_misconfiguration",
                            "known_vulnerability",
                            "vulnerability_signal",
                            "transport_security",
                            "general_security_signal",
                        )
                        rc = next(
                            (name for name in canonical_order if name in candidate_risk_classes),
                            str(risk_class or "").strip().lower() or "general_security_signal",
                        )
                        return f"planner_cluster|{severity}|{rc}|{origin}|{path}"

                    for finding in findings or []:
                        if not isinstance(finding, dict):
                            continue
                        total += 1
                        sev = str(finding.get("severity") or "INFO").strip().upper() or "INFO"
                        tool = str(finding.get("tool") or "").strip()
                        risk_class = str(finding.get("risk_class") or "").strip().lower()
                        dedup_key = str(finding.get("dedup_key") or "").strip()
                        if not dedup_key:
                            dedup_key = self._finding_dedup_key(finding)
                        if not dedup_key:
                            continue
                        phase = str(finding.get("phase") or "baseline").strip().lower() or "baseline"
                        title = str(finding.get("title") or "").strip()
                        evidence = str(finding.get("evidence") or "").strip()
                        origin, path = _surface_label_from_finding(finding)
                        target_label = ""
                        if origin:
                            target_label = origin
                            if path:
                                target_label = f"{target_label}{path}"
                        severity_rank = int(self._severity_rank(sev))
                        cluster_key = _planner_cluster_key(
                            dedup_key,
                            sev,
                            severity_rank,
                            risk_class,
                            title,
                            evidence,
                            origin,
                            path,
                        )
                        cluster = by_key.get(cluster_key)
                        if cluster is None:
                            cluster = {
                                "cluster_id": cluster_key,
                                "source_dedup_keys": set(),
                                "severity": sev,
                                "severity_rank": severity_rank,
                                "risk_class": risk_class or "general_security_signal",
                                "title": title,
                                "count": 0,
                                "tools": set(),
                                "phases": set(),
                                "targets": set(),
                                "evidence_samples": [],
                            }
                            by_key[cluster_key] = cluster
                        cluster["source_dedup_keys"].add(dedup_key)
                        cluster["count"] = int(cluster.get("count", 0)) + 1
                        if severity_rank > int(cluster.get("severity_rank", 0)):
                            cluster["severity"] = sev
                            cluster["severity_rank"] = severity_rank
                        if tool:
                            cluster["tools"].add(tool)
                        if phase:
                            cluster["phases"].add(phase)
                        if target_label:
                            cluster["targets"].add(target_label)
                        elif origin:
                            cluster["targets"].add(origin)
                        if evidence and len(cluster["evidence_samples"]) < 3:
                            cluster["evidence_samples"].append(evidence[:220])
                        if phase == "agentic":
                            include_for_correlation = True
                            if str(tool or "").strip().lower() == "browser_use":
                                finding_type = str(finding.get("type") or "").strip().lower()
                                confidence = str(finding.get("confidence") or "").strip().lower()
                                # Only browser observations (not discovery URLs) with sufficient
                                # confidence can close high-risk clusters via correlation.
                                if finding_type != "browser_observation":
                                    include_for_correlation = False
                                elif confidence and confidence not in {"medium", "high"}:
                                    include_for_correlation = False
                            if not include_for_correlation:
                                continue
                            signal_labels: List[str] = []
                            target_field = str(finding.get("target") or "").strip()
                            if target_label:
                                signal_labels.append(target_label)
                            if origin:
                                signal_labels.append(origin)
                            if target_field:
                                signal_labels.append(target_field)
                            if evidence:
                                signal_labels.extend(
                                    str(u).rstrip(".,;")
                                    for u in re.findall(r"https?://[^\s)>'\"`]+", evidence, flags=re.IGNORECASE)
                                )
                            host_ports = _host_port_keys_from_labels(signal_labels)
                            hosts_only = _host_keys_from_labels(signal_labels)
                            target_paths = _target_path_keys_from_labels(signal_labels)
                            risk_classes = _risk_match_classes(risk_class, title, evidence)
                            if target_paths:
                                for rc in risk_classes:
                                    agentic_risk_target_paths.setdefault(rc, set()).update(target_paths)
                            if host_ports:
                                for rc in risk_classes:
                                    agentic_risk_host_ports.setdefault(rc, set()).update(host_ports)
                            if hosts_only:
                                for rc in risk_classes:
                                    agentic_risk_hosts.setdefault(rc, set()).update(hosts_only)

                    clusters: List[Dict[str, Any]] = []
                    for item in by_key.values():
                        phases = sorted(str(x) for x in item.get("phases", set()) if str(x).strip())
                        targets = sorted(str(x) for x in item.get("targets", set()) if str(x).strip())
                        tools = sorted(str(x) for x in item.get("tools", set()) if str(x).strip())
                        cluster = {
                            "cluster_id": item.get("cluster_id"),
                            "severity": item.get("severity"),
                            "severity_rank": int(item.get("severity_rank", 0)),
                            "risk_class": item.get("risk_class"),
                            "title": item.get("title"),
                            "count": int(item.get("count", 0)),
                            "source_dedup_keys": sorted(
                                str(x) for x in item.get("source_dedup_keys", set()) if str(x).strip()
                            )[:8],
                            "tools": tools[:6],
                            "phases": phases,
                            "targets": targets[:6],
                            "evidence_samples": list(item.get("evidence_samples", []))[:3],
                            "seen_in_agentic": "agentic" in phases,
                        }
                        clusters.append(cluster)

                    # Cross-tool closure: if agentic findings cover same risk-class and host:port
                    # surface, treat baseline-only high-risk clusters as covered evidence.
                    for cluster in clusters:
                        if bool(cluster.get("seen_in_agentic")):
                            continue
                        if int(cluster.get("severity_rank", 0)) < 4:
                            continue
                        rc = str(cluster.get("risk_class") or "").strip().lower() or "general_security_signal"
                        cluster_host_ports = _host_port_keys_from_labels(cluster.get("targets", []) or [])
                        cluster_target_paths = _target_path_keys_from_labels(cluster.get("targets", []) or [])
                        evidence_blob = " ".join(str(x or "") for x in (cluster.get("evidence_samples") or []))
                        if evidence_blob:
                            cluster_target_paths.update(
                                _target_path_keys_from_labels(
                                    [
                                        str(u).rstrip(".,;")
                                        for u in re.findall(r"https?://[^\s)>'\"`]+", evidence_blob, flags=re.IGNORECASE)
                                    ]
                                )
                            )
                            cluster_host_ports.update(
                                _host_port_keys_from_labels(
                                    [
                                        str(u).rstrip(".,;")
                                        for u in re.findall(r"https?://[^\s)>'\"`]+", evidence_blob, flags=re.IGNORECASE)
                                    ]
                                )
                            )
                        cluster_hosts = _host_keys_from_labels(cluster.get("targets", []) or [])
                        if evidence_blob:
                            cluster_hosts.update(
                                _host_keys_from_labels(
                                    [
                                        str(u).rstrip(".,;")
                                        for u in re.findall(r"https?://[^\s)>'\"`]+", evidence_blob, flags=re.IGNORECASE)
                                    ]
                                )
                            )
                        if not cluster_host_ports and not cluster_hosts:
                            continue
                        candidate_risk_classes = _risk_match_classes(
                            rc,
                            str(cluster.get("title") or ""),
                            evidence_blob,
                        )
                        matched = False
                        for risk_name in candidate_risk_classes:
                            seen_paths = agentic_risk_target_paths.get(risk_name, set())
                            seen_ports = agentic_risk_host_ports.get(risk_name, set())
                            seen_hosts = agentic_risk_hosts.get(risk_name, set())
                            if seen_paths and cluster_target_paths and (cluster_target_paths & seen_paths):
                                matched = True
                                break
                            if seen_ports and cluster_host_ports and (cluster_host_ports & seen_ports):
                                matched = True
                                break
                            if (not seen_ports and not cluster_host_ports) and seen_hosts and cluster_hosts and (
                                cluster_hosts & seen_hosts
                            ):
                                matched = True
                                break
                        if matched:
                            cluster["seen_in_agentic"] = True
                            cluster["seen_in_agentic_via_correlation"] = True

                    clusters.sort(
                        key=lambda c: (
                            -int(c.get("severity_rank", 0)),
                            -int(c.get("count", 0)),
                            str(c.get("title") or ""),
                        )
                    )

                    open_high_risk_clusters = [
                        {
                            "cluster_id": c.get("cluster_id"),
                            "severity": c.get("severity"),
                            "risk_class": c.get("risk_class"),
                            "title": c.get("title"),
                            "count": c.get("count"),
                            "targets": c.get("targets", [])[:4],
                            "tools": c.get("tools", [])[:4],
                            "evidence_samples": c.get("evidence_samples", [])[:3],
                        }
                        for c in clusters
                        if int(c.get("severity_rank", 0)) >= 4 and not bool(c.get("seen_in_agentic"))
                    ][:30]
                    covered_cluster_ids = [str(c.get("cluster_id") or "") for c in clusters if bool(c.get("seen_in_agentic"))][:80]
                    return {
                        "total_findings": int(total),
                        "cluster_count": len(clusters),
                        "clusters": clusters[:140],
                        "open_high_risk_clusters": open_high_risk_clusters,
                        "covered_cluster_ids": covered_cluster_ids,
                    }

                def _planner_action_ledger_snapshot(limit: int = 100) -> List[Dict[str, Any]]:
                    if limit <= 0:
                        return []
                    return [dict(x) for x in planner_action_ledger[-int(limit) :] if isinstance(x, dict)]

                def _candidate_sort_key(action: Dict[str, Any]) -> Tuple[int, int, str, str]:
                    skip_penalty = 1 if _baseline_would_skip(action) else 0
                    priority = clamp_int(action.get("priority"), default=50, minimum=1, maximum=100)
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    target = str(args.get("target") or "")
                    tool = str(action.get("tool") or "")
                    return (skip_penalty, priority, tool, target)

                def _action_novelty(action: Dict[str, Any]) -> int:
                    """
                    Generic novelty score to avoid repetitive low-value loops.
                    Higher is better.
                    """
                    if not isinstance(action, dict):
                        return 0
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    tool = str(action.get("tool") or "").strip().lower()
                    target = str(args.get("target") or "").strip()
                    score = 0
                    if target and target not in agentic_target_counts:
                        score += 2
                    if tool and tool not in agentic_tool_counts:
                        score += 1
                    if tool and int(agentic_tool_risk_gain_counts.get(tool, 0)) > 0:
                        score += 1
                    if tool and int(agentic_tool_no_risk_gain_counts.get(tool, 0)) >= 2:
                        score -= 2
                    if target and agentic_target_counts.get(target, 0) >= 2:
                        score -= 1
                    if tool and agentic_tool_counts.get(tool, 0) >= 3:
                        score -= 1
                    return score

                def _action_gain_score(action: Dict[str, Any]) -> int:
                    """
                    Predict likely value from this action using generic historical signal.
                    Positive means likely useful, negative means likely diminishing returns.
                    """
                    if not isinstance(action, dict):
                        return -1
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    tool = str(action.get("tool") or "").strip().lower()
                    target = str(args.get("target") or "").strip()
                    score = int(_action_novelty(action))
                    open_high_risk_count_now = len(_open_high_risk_clusters_now())

                    history = agentic_tool_gain_scores.get(tool, [])
                    if history:
                        window = history[-3:]
                        avg_gain = float(sum(window)) / float(max(1, len(window)))
                        if avg_gain >= 3.0:
                            score += 2
                        elif avg_gain <= 0.0:
                            score -= 2

                    if tool and int(agentic_low_signal_tool_counts.get(tool, 0)) >= 2:
                        score -= 2

                    if tool == "sslscan" and _resolve_sslscan_port_for_action(action) is None:
                        score -= 4

                    if tool == "nuclei":
                        high_risk_targets = _high_risk_web_targets_now()
                        if baseline_broad_nuclei_targets and target and target in baseline_broad_nuclei_targets:
                            if high_risk_targets and target not in high_risk_targets:
                                score -= 3
                        if int(agentic_tool_no_risk_gain_counts.get(tool, 0)) >= 2:
                            score -= 2

                    if open_high_risk_count_now <= 0:
                        resolved_target = _resolve_allowed_web_target(tool, target) if target else None
                        target_ranks = _target_max_severity_ranks_now()
                        target_rank = 0
                        if resolved_target and resolved_target in target_ranks:
                            target_rank = int(target_ranks.get(resolved_target, 0))
                        elif target and target in target_ranks:
                            target_rank = int(target_ranks.get(target, 0))

                        if tool in ("nuclei", "sslscan", "browser_use", "gobuster", "ffuf", "katana"):
                            if target_rank < 3:
                                score -= 4
                            elif target_rank < 4:
                                score -= 2
                        elif tool in ("whatweb", "httpx") and target_rank < 3:
                            score -= 2

                        if tool in ("nuclei", "sslscan") and int(agentic_tool_no_risk_gain_counts.get(tool, 0)) >= 1:
                            score -= 2
                        if tool == "browser_use" and int(agentic_tool_no_risk_gain_counts.get(tool, 0)) >= 1:
                            score -= 2

                    return score

                def _action_repeat_key(action: Dict[str, Any], result_entry: Optional[Dict[str, Any]] = None) -> Optional[Tuple[str, str]]:
                    if not isinstance(action, dict):
                        return None
                    tool = str(action.get("tool") or "").strip().lower()
                    if not tool:
                        return None
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    target_kind = str(tool_specs.get(tool, {}).get("target_kind") or "").strip().lower()
                    target = str(args.get("target") or "").strip()

                    if tool == "sslscan":
                        resolved_port = _resolve_sslscan_port_for_action(action, result_entry=result_entry)
                        port_txt = str(int(resolved_port)) if resolved_port is not None else "auto"
                        return (tool, f"{scan_host}:{port_txt}")

                    if target_kind == "web":
                        return (tool, target or "__missing_target__")
                    if target_kind in ("host", "host_port"):
                        return (tool, str(scan_host or "").strip() or "__host__")
                    if target_kind == "container":
                        return (tool, str(container_image or "").strip() or "__container__")
                    return (tool, target or "__global__")

                def _repeat_limits_for_tool(tool: str) -> Dict[str, int]:
                    t = str(tool or "").strip().lower()
                    if t == "sslscan":
                        tls_count = len(tls_ports) if isinstance(tls_ports, list) else 0
                        return {
                            "max_per_pair": 1,
                            "max_total": max(1, min(3, tls_count or 1)),
                            "max_low_signal": 1,
                        }
                    if t == "nuclei":
                        web_count = len(allowed_web_targets) if isinstance(allowed_web_targets, list) else 0
                        if baseline_broad_nuclei_targets:
                            dynamic_total = 2 if web_count >= 2 else 1
                            return {
                                "max_per_pair": 1,
                                "max_total": dynamic_total,
                                "max_low_signal": 1,
                            }
                        dynamic_total = max(2, min(5, max(2, web_count // 2))) if web_count else 4
                        return {
                            "max_per_pair": 2,
                            "max_total": dynamic_total,
                            "max_low_signal": 2,
                        }
                    if t in ("whatweb", "gobuster", "ffuf", "katana"):
                        return {"max_per_pair": 1, "max_total": 3, "max_low_signal": 2}
                    if t == "browser_use":
                        return {"max_per_pair": 1, "max_total": 2, "max_low_signal": 1}
                    return {"max_per_pair": 2, "max_total": 5, "max_low_signal": 3}

                def _repeat_block_reason(action: Dict[str, Any]) -> Optional[str]:
                    key = _action_repeat_key(action)
                    if not key:
                        return None
                    tool = key[0]
                    limits = _repeat_limits_for_tool(tool)
                    pair_count = int(agentic_action_counts.get(key, 0))
                    tool_count = int(agentic_tool_counts.get(tool, 0))
                    low_signal_count = int(agentic_low_signal_tool_counts.get(tool, 0))
                    novelty = int(_action_novelty(action))
                    gain_score = int(_action_gain_score(action))
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    target = str(args.get("target") or "").strip()

                    if tool == "sslscan" and _resolve_sslscan_port_for_action(action) is None:
                        return "invalid_sslscan_target"

                    if tool == "sqlmap":
                        normalized_sql_target = self._normalize_sqlmap_candidate_url(target)
                        if normalized_sql_target and normalized_sql_target in sqlmap_rejected_targets:
                            return "sqlmap_target_nonviable"

                    if tool == "gobuster" and target in gobuster_wildcard_targets:
                        return "gobuster_wildcard_target"

                    if tool == "browser_use":
                        resolved_target = _resolve_allowed_web_target("browser_use", target or "")
                        if target and (target in browser_use_fallback_block_targets):
                            return "browser_use_fallback_no_cluster_closure"
                        if resolved_target and resolved_target in browser_use_fallback_block_targets:
                            return "browser_use_fallback_no_cluster_closure"

                    if (
                        tool in ("nuclei", "sslscan", "gobuster", "ffuf", "katana", "browser_use", "nikto", "sqlmap")
                        and tool_count >= 1
                        and novelty <= 0
                        and gain_score <= 0
                        and not _action_links_open_high_risk_cluster(action)
                    ):
                        return "low_gain_not_linked_open_high_risk"

                    if tool == "nuclei":
                        high_risk_targets = _high_risk_web_targets_now()
                        if (
                            baseline_broad_nuclei_targets
                            and target
                            and target in baseline_broad_nuclei_targets
                            and high_risk_targets
                            and target not in high_risk_targets
                            and tool_count >= 1
                        ):
                            return "nuclei_broad_covered_low_risk"
                        history = agentic_tool_gain_scores.get(tool, [])
                        if len(history) >= 2 and sum(history[-2:]) <= 1 and novelty <= 1:
                            return "tool_low_gain_repeat_cap"
                    if pair_count >= int(limits.get("max_per_pair", 1)):
                        return "tool_target_repeat_cap"
                    if tool == "nuclei" and baseline_broad_nuclei_targets and tool_count >= int(limits.get("max_total", 1)):
                        return "tool_repeat_cap"
                    if tool_count >= int(limits.get("max_total", 1)) and (novelty <= 1 or gain_score <= 0):
                        return "tool_repeat_cap"
                    if tool == "sslscan" and low_signal_count >= int(limits.get("max_low_signal", 1)):
                        return "tool_low_signal_repeat_cap"
                    if low_signal_count >= int(limits.get("max_low_signal", 1)) and (novelty <= 1 or gain_score <= 0):
                        return "tool_low_signal_repeat_cap"
                    return None

                def _summarize_action_for_log(action: Dict[str, Any]) -> str:
                    if not isinstance(action, dict):
                        return "unknown"
                    tool = str(action.get("tool") or "unknown").strip() or "unknown"
                    args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                    target = str(args.get("target") or "").strip()
                    priority = clamp_int(action.get("priority"), default=50, minimum=1, maximum=100)
                    hint = f"{tool} p{priority}"
                    if tool == "sslscan":
                        resolved_port = _resolve_sslscan_port_for_action(action)
                        if resolved_port is not None:
                            hint = f"{hint} :{resolved_port}"
                    if target:
                        hint = f"{hint} @{target}"
                    return hint

                def _short_text(value: Any, max_len: int = 180) -> str:
                    text = str(value or "").strip()
                    if not text:
                        return ""
                    text = " ".join(text.split())
                    if len(text) <= max_len:
                        return text
                    return text[: max_len - 3].rstrip() + "..."

                def _validate_browser_discovery_urls(
                    action: Dict[str, Any],
                    entry: Dict[str, Any],
                ) -> None:
                    if not isinstance(action, dict) or not isinstance(entry, dict):
                        return
                    if str(action.get("tool") or "").strip().lower() != "browser_use":
                        return
                    if not bool(entry.get("success")):
                        return
                    data = entry.get("data") if isinstance(entry.get("data"), dict) else None
                    if not isinstance(data, dict):
                        return
                    urls_raw = data.get("urls")
                    if not isinstance(urls_raw, list):
                        return

                    validation_block: Dict[str, Any] = {
                        "attempted": False,
                        "candidate_count": 0,
                        "validated_count": 0,
                        "validated_urls": [],
                        "httpx_success": False,
                        "url_hygiene": {
                            "canonicalized": [],
                            "suppressed_malformed": 0,
                            "suppressed_by_status": 0,
                            "suppressed_duplicate": 0,
                            "same_origin_filtered": 0,
                        },
                    }
                    data["browser_discovery_validation"] = validation_block

                    if not self._has_scanner("httpx") or not self._tool_enabled("httpx", default=True):
                        return

                    base_target = str(entry.get("target") or (action.get("arguments") or {}).get("target") or "").strip()
                    base_hp = _web_target_host_port_key(base_target)
                    candidates: List[str] = []
                    seen_candidates: Set[str] = set()
                    url_hygiene = validation_block.get("url_hygiene") if isinstance(validation_block.get("url_hygiene"), dict) else {}
                    sanitized_urls_for_data: List[str] = []
                    for raw in urls_raw:
                        original_url = str(raw or "").strip()
                        url = _sanitize_browser_url_candidate(original_url, base_target=base_target)
                        if not url:
                            url_hygiene["suppressed_malformed"] = int(url_hygiene.get("suppressed_malformed", 0)) + 1
                            continue
                        if url != original_url:
                            canonicalized = url_hygiene.setdefault("canonicalized", [])
                            if isinstance(canonicalized, list):
                                canonicalized.append({"from": original_url, "to": url})
                        if url in seen_candidates:
                            url_hygiene["suppressed_duplicate"] = int(url_hygiene.get("suppressed_duplicate", 0)) + 1
                            continue
                        hp = _web_target_host_port_key(url)
                        if base_hp is not None and hp is not None and hp != base_hp:
                            url_hygiene["same_origin_filtered"] = int(url_hygiene.get("same_origin_filtered", 0)) + 1
                            continue
                        seen_candidates.add(url)
                        candidates.append(url)
                        sanitized_urls_for_data.append(url)
                        if len(candidates) >= 16:
                            break
                    data["urls"] = sanitized_urls_for_data[:100]
                    if not candidates:
                        return

                    validation_block["candidate_count"] = len(candidates)
                    validation_block["attempted"] = True
                    try:
                        result = self.scanners["httpx"].scan(
                            candidates,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("httpx"),
                        )
                    except Exception as e:
                        validation_block["error"] = str(e)
                        return
                    if not isinstance(result, dict):
                        return
                    validation_block["httpx_success"] = bool(result.get("success"))
                    if not bool(result.get("success")):
                        validation_block["error"] = str(result.get("error") or "")
                        return
                    alive = result.get("alive") if isinstance(result.get("alive"), list) else []
                    validated_urls = []
                    seen_validated: Set[str] = set()
                    for raw in alive:
                        url = str(raw or "").strip()
                        if not url or url in seen_validated:
                            continue
                        seen_validated.add(url)
                        validated_urls.append(url)
                    validation_block["validated_urls"] = validated_urls[:32]
                    validation_block["validated_count"] = len(validated_urls)
                    results_rows = result.get("results") if isinstance(result.get("results"), list) else []
                    if results_rows:
                        status_map: Dict[str, Any] = {}
                        for row in results_rows:
                            if not isinstance(row, dict):
                                continue
                            url = str(row.get("url") or "").strip()
                            if not url or url in status_map:
                                continue
                            status = row.get("status_code")
                            if status is None:
                                status = row.get("status-code")
                            if status is None:
                                status = row.get("status")
                            if status is None:
                                continue
                            status_map[url] = status
                        if status_map:
                            validation_block["status_by_url"] = status_map
                            kept_urls: List[str] = []
                            for url in data.get("urls") or []:
                                status = status_map.get(url)
                                try:
                                    status_int = int(status) if status is not None else None
                                except Exception:
                                    status_int = None
                                if status_int in {404, 410}:
                                    url_hygiene["suppressed_by_status"] = int(url_hygiene.get("suppressed_by_status", 0)) + 1
                                    continue
                                kept_urls.append(str(url))
                            data["urls"] = kept_urls[:100]
                            validation_block["validated_urls"] = [
                                str(url)
                                for url in validated_urls
                                if str(url) in set(data.get("urls") or [])
                            ][:32]
                            validation_block["validated_count"] = len(validation_block["validated_urls"])

                def _restrict_browser_use_result_scope(
                    action: Dict[str, Any],
                    entry: Dict[str, Any],
                ) -> None:
                    if not isinstance(action, dict) or not isinstance(entry, dict):
                        return
                    if str(action.get("tool") or "").strip().lower() != "browser_use":
                        return
                    if not bool(entry.get("success")):
                        return
                    data = entry.get("data") if isinstance(entry.get("data"), dict) else None
                    if not isinstance(data, dict):
                        return
                    base_target = str(entry.get("target") or (action.get("arguments") or {}).get("target") or "").strip()
                    base_hp = _web_target_host_port_key(base_target)
                    if base_hp is None:
                        return

                    urls_raw = data.get("urls")
                    if isinstance(urls_raw, list):
                        filtered_urls: List[str] = []
                        removed_urls = 0
                        seen_urls: Set[str] = set()
                        for raw in urls_raw:
                            url = _sanitize_browser_url_candidate(raw, base_target=base_target)
                            if not url:
                                continue
                            hp = _web_target_host_port_key(url)
                            if hp is not None and hp != base_hp:
                                removed_urls += 1
                                continue
                            if url in seen_urls:
                                continue
                            seen_urls.add(url)
                            filtered_urls.append(url)
                        data["urls"] = filtered_urls
                        if removed_urls > 0:
                            data["scope_filter"] = {
                                "same_origin_only": True,
                                "removed_cross_origin_urls": int(removed_urls),
                            }

                    findings_raw = data.get("findings")
                    if isinstance(findings_raw, list):
                        filtered_findings: List[Dict[str, Any]] = []
                        removed_findings = 0
                        for item in findings_raw:
                            if not isinstance(item, dict):
                                continue
                            sanitized_item = dict(item)
                            for field_name in ("evidence", "title", "target"):
                                raw_value = sanitized_item.get(field_name)
                                if isinstance(raw_value, str) and raw_value.strip():
                                    sanitized_item[field_name] = _sanitize_browser_urls_in_text(
                                        raw_value,
                                        base_target=base_target,
                                    )
                            explicit_urls: List[str] = []
                            for field_name in ("evidence", "title", "target"):
                                raw_value = sanitized_item.get(field_name)
                                if isinstance(raw_value, str) and raw_value.strip().startswith(("http://", "https://")):
                                    explicit_urls.append(
                                        _sanitize_browser_url_candidate(raw_value.strip(), base_target=base_target)
                                    )
                                explicit_urls.extend(_urls_from_text(raw_value))
                            explicit_urls = [str(x).strip() for x in explicit_urls if str(x).strip()]
                            if explicit_urls:
                                same_origin_seen = False
                                off_origin_seen = False
                                for url in explicit_urls:
                                    hp = _web_target_host_port_key(url)
                                    if hp == base_hp:
                                        same_origin_seen = True
                                    elif hp is not None:
                                        off_origin_seen = True
                                if off_origin_seen and not same_origin_seen:
                                    removed_findings += 1
                                    continue
                            filtered_findings.append(sanitized_item)
                        data["findings"] = filtered_findings
                        if removed_findings > 0:
                            scope_filter = data.get("scope_filter") if isinstance(data.get("scope_filter"), dict) else {}
                            scope_filter["removed_cross_origin_findings"] = int(removed_findings)
                            scope_filter["same_origin_only"] = True
                            data["scope_filter"] = scope_filter

                while actions_executed < int(max_actions):
                    if canceled():
                        break
                    sqlmap_plan = self._build_sqlmap_targets(
                        normalized,
                        web_targets=allowed_web_targets,
                        results=agg.get("results", []),
                        max_targets=sqlmap_max_targets,
                        blocked_targets=sorted(sqlmap_rejected_targets),
                        return_plan=True,
                    )
                    sqlmap_targets = (
                        list(sqlmap_plan.get("targets", []))
                        if isinstance(sqlmap_plan, dict) and isinstance(sqlmap_plan.get("targets"), list)
                        else []
                    )
                    if isinstance(sqlmap_plan, dict):
                        for item in sqlmap_plan.get("rejected_targets", []) or []:
                            value = str(item or "").strip()
                            if value:
                                sqlmap_rejected_targets.add(value)
                    remaining = int(max_actions) - actions_executed
                    open_high_risk_clusters = _open_high_risk_clusters_now()
                    coverage_debt_open_count = len(open_high_risk_clusters)
                    trace_item: Dict[str, Any] = {
                        "iteration": int(actions_executed) + 1,
                        "remaining_actions_before": int(remaining),
                        "started_at": time.time(),
                        "open_high_risk_cluster_count_before": int(coverage_debt_open_count),
                    }
                    if (
                        coverage_debt_open_count <= 0
                        and any(
                            int(x.get("open_high_risk_cluster_delta", 0)) > 0
                            for x in (planner_action_ledger[-6:] if isinstance(planner_action_ledger, list) else [])
                            if isinstance(x, dict)
                        )
                    ):
                        recent_ledger_window = [
                            x
                            for x in (planner_action_ledger[-2:] if isinstance(planner_action_ledger, list) else [])
                            if isinstance(x, dict)
                        ]
                        recent_net_new_sum = sum(
                            int(x.get("agentic_net_new_unique_delta", 0)) for x in recent_ledger_window
                        )
                        recent_risk_delta_sum = sum(int(x.get("risk_class_delta", 0)) for x in recent_ledger_window)
                        recent_open_high_risk_delta_sum = sum(
                            int(x.get("open_high_risk_cluster_delta", 0)) for x in recent_ledger_window
                        )
                        recent_gain_sum_2 = sum(int(x) for x in recent_gain_scores[-2:]) if len(recent_gain_scores) >= 2 else 0
                        if (
                            len(recent_ledger_window) >= 2
                            and low_signal_streak >= 2
                            and recent_open_high_risk_delta_sum <= 0
                            and recent_risk_delta_sum <= 0
                            and recent_net_new_sum <= 1
                            and len(recent_gain_scores) >= 2
                            and recent_gain_sum_2 <= 1
                        ):
                            note(
                                "llm_decision",
                                "planner",
                                "diminishing returns: post-closure marginal signal exhausted; stopping",
                                agg=agg,
                            )
                            trace_item["decision"] = {
                                "result": "stop",
                                "reason": "post_closure_low_marginal_signal",
                            }
                            trace_item["finished_at"] = time.time()
                            ai_obj.setdefault("decision_trace", []).append(trace_item)
                            break
                    if (
                        coverage_debt_open_count <= 0
                        and low_signal_streak >= 3
                        and len(recent_gain_scores) >= 3
                        and sum(recent_gain_scores[-3:]) <= 0
                    ):
                        note(
                            "llm_decision",
                            "planner",
                            "diminishing returns: recent gain exhausted; stopping",
                            agg=agg,
                        )
                        trace_item["decision"] = {
                            "result": "stop",
                            "reason": "diminishing_returns_recent_gain_exhausted",
                        }
                        trace_item["finished_at"] = time.time()
                        ai_obj.setdefault("decision_trace", []).append(trace_item)
                        break
                    if (
                        coverage_debt_open_count <= 0
                        and baseline_broad_nuclei_targets
                        and nonpositive_after_broad_streak >= 2
                    ):
                        note(
                            "llm_decision",
                            "planner",
                            "diminishing returns: forced pivot exhausted after consecutive non-positive gain actions; stopping",
                            agg=agg,
                        )
                        trace_item["decision"] = {
                            "result": "stop",
                            "reason": "forced_pivot_exhausted_nonpositive_gain",
                        }
                        trace_item["finished_at"] = time.time()
                        ai_obj.setdefault("decision_trace", []).append(trace_item)
                        break
                    if coverage_debt_open_count > 0:
                        note(
                            "llm_decision",
                            "planner",
                            (
                                "coverage debt active: "
                                f"{int(coverage_debt_open_count)} open high-risk cluster(s); "
                                "prioritizing cluster-linked actions before normal stop."
                            ),
                            agg=agg,
                        )
                    action: Optional[Dict[str, Any]] = None
                    stop_requested = False
                    replan_attempted = False
                    # Pre-seed exclusions on the very first planner call of each iteration
                    # so compliant models avoid proposing already-covered actions.
                    excluded_actions_for_replan: List[Dict[str, Any]] = _covered_action_exclusions()

                    while True:
                        try:
                            plan = plan_actions(remaining, excluded_actions=excluded_actions_for_replan)
                        except ToolCallingNotSupported as e:
                            msg = f"Tool calling not supported; skipping agentic phase. ({e})"
                            ai_obj["planner"]["warning"] = msg
                            ai_obj["agentic_skipped"] = True
                            note("llm_error", "planner", msg, agg=agg)
                            trace_item["planner_error"] = msg
                            trace_item["decision"] = {"result": "stop", "reason": "planner_not_supported"}
                            trace_item["finished_at"] = time.time()
                            ai_obj.setdefault("decision_trace", []).append(trace_item)
                            action = None
                            break
                        except (ToolCallingError, Exception) as e:
                            msg = f"Tool calling failed; skipping agentic phase. ({e})"
                            ai_obj["planner"]["warning"] = msg
                            ai_obj["agentic_skipped"] = True
                            note("llm_error", "planner", msg, agg=agg)
                            trace_item["planner_error"] = msg
                            trace_item["decision"] = {"result": "stop", "reason": "planner_failure"}
                            trace_item["finished_at"] = time.time()
                            ai_obj.setdefault("decision_trace", []).append(trace_item)
                            action = None
                            break

                        plan_actions_list = [a for a in (plan.get("actions", []) or []) if isinstance(a, dict)]
                        sorted_candidates = sorted(plan_actions_list, key=_candidate_sort_key)
                        ai_obj["planner"]["plans"].append(
                            {"actions": plan_actions_list, "notes": plan.get("notes", ""), "stop": plan.get("stop", False)}
                        )
                        planner_view = {
                            "stop": bool(plan.get("stop")),
                            "notes": plan.get("notes", ""),
                            "candidate_count": len(plan_actions_list),
                            "candidates": [_action_trace_view(a) for a in sorted_candidates[:8]],
                        }
                        if not replan_attempted:
                            trace_item["planner"] = planner_view
                        else:
                            trace_item.setdefault("planner_replans", []).append(planner_view)

                        if sorted_candidates:
                            top = "; ".join(_summarize_action_for_log(a) for a in sorted_candidates[:3])
                        else:
                            top = "none"
                        plan_msg = f"iteration={trace_item['iteration']} candidates={len(sorted_candidates)} top={top}"
                        if replan_attempted:
                            plan_msg = f"{plan_msg} replan=1"
                        note("llm_plan", "planner", plan_msg, agg=agg)

                        if plan.get("notes"):
                            ai_obj["notes"] = plan.get("notes")
                        stop_requested = stop_requested or bool(plan.get("stop"))
                        if not sorted_candidates:
                            if coverage_debt_open_count > 0:
                                trace_item["unresolved_high_risk_clusters"] = open_high_risk_clusters[:10]
                            trace_item["decision"] = {
                                "result": "stop",
                                "reason": (
                                    "unresolved_high_risk_no_actionable_candidates"
                                    if coverage_debt_open_count > 0
                                    else ("planner_stop" if stop_requested else "no_actions")
                                ),
                            }
                            trace_item["finished_at"] = time.time()
                            ai_obj.setdefault("decision_trace", []).append(trace_item)
                            action = None
                            break

                        actionable_after_coverage = [a for a in sorted_candidates if not _baseline_would_skip(a)]
                        repeat_blocked: List[Dict[str, Any]] = []
                        repeat_blocked_reasons: Dict[Tuple[str, str], str] = {}
                        actionable: List[Dict[str, Any]] = []
                        for cand in actionable_after_coverage:
                            block_reason = _repeat_block_reason(cand)
                            if block_reason:
                                repeat_blocked.append(cand)
                                repeat_key = _action_repeat_key(cand)
                                if repeat_key:
                                    repeat_blocked_reasons[repeat_key] = block_reason
                                continue
                            actionable.append(cand)

                        if repeat_blocked:
                            blocked_preview = [
                                {
                                    "tool": _action_trace_view(a).get("tool"),
                                    "target": _action_trace_view(a).get("target"),
                                    "port": _action_trace_view(a).get("port"),
                                    "priority": _action_trace_view(a).get("priority"),
                                    "reason": repeat_blocked_reasons.get(_action_repeat_key(a) or ("", ""), "repeat_policy"),
                                }
                                for a in repeat_blocked[:8]
                            ]
                            planner_blocked_candidates.extend(
                                [
                                    {
                                        "iteration": int(trace_item.get("iteration") or 0),
                                        "tool": item.get("tool"),
                                        "target": item.get("target"),
                                        "port": item.get("port"),
                                        "priority": item.get("priority"),
                                        "reason": item.get("reason"),
                                    }
                                    for item in blocked_preview
                                    if isinstance(item, dict)
                                ]
                            )
                            if len(planner_blocked_candidates) > 500:
                                planner_blocked_candidates = planner_blocked_candidates[-500:]
                            trace_item["repeat_filtered"] = {
                                "count": len(repeat_blocked),
                                "candidates": blocked_preview,
                            }
                            note(
                                "llm_decision",
                                "planner",
                                f"repeat policy filtered {len(repeat_blocked)} candidate(s)",
                                agg=agg,
                            )

                        if coverage_debt_open_count > 0 and not actionable:
                            pivot_candidates = _build_coverage_debt_pivot_actions(
                                open_high_risk_clusters,
                                repeat_blocked,
                                repeat_blocked_reasons,
                            )
                            if pivot_candidates:
                                coverage_debt_pivot_count = int(coverage_debt_pivot_count) + 1
                                actionable = list(pivot_candidates)
                                trace_item["coverage_debt_pivot"] = {
                                    "attempted": True,
                                    "pivot_count": int(coverage_debt_pivot_count),
                                    "reason": (
                                        "nuclei_repeat_blocked_with_open_high_risk"
                                        if repeat_blocked
                                        else "coverage_debt_no_actionable_candidates"
                                    ),
                                    "injected_count": len(pivot_candidates),
                                    "injected": [_action_trace_view(a) for a in pivot_candidates[:6]],
                                }
                                note(
                                    "llm_decision",
                                    "planner",
                                    "coverage debt pivot injected "
                                    f"{len(pivot_candidates)} cluster-derived candidate(s)",
                                    agg=agg,
                                )

                        if actionable:
                            if coverage_debt_open_count > 0:
                                linked_actionable = [a for a in actionable if _action_links_open_high_risk_cluster(a)]
                                if linked_actionable:
                                    actionable = linked_actionable
                                    trace_item["coverage_debt_filter"] = {
                                        "active": True,
                                        "open_high_risk_cluster_count": int(coverage_debt_open_count),
                                        "linked_candidates_count": len(linked_actionable),
                                        "unresolved_clusters_preview": [
                                            {
                                                "cluster_id": str(c.get("cluster_id") or ""),
                                                "severity": str(c.get("severity") or ""),
                                                "risk_class": str(c.get("risk_class") or ""),
                                                "title": str(c.get("title") or ""),
                                            }
                                            for c in open_high_risk_clusters[:6]
                                            if isinstance(c, dict)
                                        ],
                                    }
                                else:
                                    pivot_candidates = _build_coverage_debt_pivot_actions(
                                        open_high_risk_clusters,
                                        repeat_blocked,
                                        repeat_blocked_reasons,
                                    )
                                    if pivot_candidates:
                                        coverage_debt_pivot_count = int(coverage_debt_pivot_count) + 1
                                        actionable = list(pivot_candidates)
                                        trace_item["coverage_debt_pivot"] = {
                                            "attempted": True,
                                            "pivot_count": int(coverage_debt_pivot_count),
                                            "reason": "no_open_high_risk_linked_candidates",
                                            "injected_count": len(pivot_candidates),
                                            "injected": [_action_trace_view(a) for a in pivot_candidates[:6]],
                                        }
                                        note(
                                            "llm_decision",
                                            "planner",
                                            (
                                                "coverage debt pivot injected "
                                                f"{len(pivot_candidates)} cluster-derived candidate(s)"
                                            ),
                                            agg=agg,
                                        )
                                        linked_actionable = [
                                            a for a in actionable if _action_links_open_high_risk_cluster(a)
                                        ]
                                        if linked_actionable:
                                            actionable = linked_actionable
                                            trace_item["coverage_debt_filter"] = {
                                                "active": True,
                                                "open_high_risk_cluster_count": int(coverage_debt_open_count),
                                                "linked_candidates_count": len(linked_actionable),
                                                "unresolved_clusters_preview": [
                                                    {
                                                        "cluster_id": str(c.get("cluster_id") or ""),
                                                        "severity": str(c.get("severity") or ""),
                                                        "risk_class": str(c.get("risk_class") or ""),
                                                        "title": str(c.get("title") or ""),
                                                    }
                                                    for c in open_high_risk_clusters[:6]
                                                    if isinstance(c, dict)
                                                ],
                                            }
                                        else:
                                            actionable = []
                                    if not actionable and not replan_attempted:
                                        replan_attempted = True
                                        excluded_actions_for_replan = _covered_action_exclusions(sorted_candidates)
                                        trace_item["replan"] = {
                                            "attempted": True,
                                            "reason": "no_open_high_risk_linked_candidates",
                                            "excluded_count": len(excluded_actions_for_replan),
                                            "excluded": [_action_trace_view(a) for a in excluded_actions_for_replan],
                                        }
                                        note(
                                            "llm_decision",
                                            "planner",
                                            (
                                                "coverage debt active but no candidate linked to unresolved high-risk "
                                                "clusters; replanning with broader exclusions"
                                            ),
                                            agg=agg,
                                        )
                                        continue
                                    if not actionable:
                                        trace_item["unresolved_high_risk_clusters"] = open_high_risk_clusters[:10]
                                        trace_item["decision"] = {
                                            "result": "stop",
                                            "reason": "unresolved_high_risk_no_actionable_candidates",
                                        }
                                        trace_item["finished_at"] = time.time()
                                        ai_obj.setdefault("decision_trace", []).append(trace_item)
                                        action = None
                                        break

                            actionable.sort(
                                key=lambda a: (
                                    -_action_gain_score(a),
                                    -_action_novelty(a),
                                    _candidate_sort_key(a),
                                )
                            )
                            if coverage_debt_open_count <= 0:
                                positive_actionable = [a for a in actionable if _action_gain_score(a) > 0]
                                if positive_actionable:
                                    actionable = positive_actionable
                                elif actions_executed > 0:
                                    note(
                                        "llm_decision",
                                        "planner",
                                        "diminishing returns: post-closure marginal signal exhausted; stopping",
                                        agg=agg,
                                    )
                                    trace_item["decision"] = {
                                        "result": "stop",
                                        "reason": "post_closure_low_marginal_signal",
                                    }
                                    trace_item["finished_at"] = time.time()
                                    ai_obj.setdefault("decision_trace", []).append(trace_item)
                                    action = None
                                    break
                            best_novelty = _action_novelty(actionable[0])
                            best_gain = _action_gain_score(actionable[0])
                            trace_item["candidate_novelty"] = {
                                "best": int(best_novelty),
                                "best_gain_score": int(best_gain),
                                "top": [
                                    {
                                        "tool": _action_trace_view(a).get("tool"),
                                        "target": _action_trace_view(a).get("target"),
                                        "priority": _action_trace_view(a).get("priority"),
                                        "novelty": int(_action_novelty(a)),
                                        "gain_score": int(_action_gain_score(a)),
                                    }
                                    for a in actionable[:5]
                                ],
                            }
                            if baseline_broad_nuclei_targets and nonpositive_after_broad_streak == 1 and not replan_attempted:
                                replan_attempted = True
                                pivot_exclusions = actionable[:2] + sorted_candidates[:4]
                                excluded_actions_for_replan = _covered_action_exclusions(pivot_exclusions)
                                trace_item["replan"] = {
                                    "attempted": True,
                                    "reason": "recent_nonpositive_gain_forced_pivot",
                                    "excluded_count": len(excluded_actions_for_replan),
                                    "excluded": [_action_trace_view(a) for a in excluded_actions_for_replan],
                                }
                                note(
                                    "llm_decision",
                                    "planner",
                                    "recent non-positive gain detected; forcing one pivot replan",
                                    agg=agg,
                                )
                                continue
                            if coverage_debt_open_count <= 0 and low_signal_streak >= 2 and best_gain <= 0:
                                note(
                                    "llm_decision",
                                    "planner",
                                    "diminishing returns: low recent signal and low gain candidates; stopping",
                                    agg=agg,
                                )
                                trace_item["decision"] = {
                                    "result": "stop",
                                    "reason": "diminishing_returns_low_signal_low_gain",
                                }
                                trace_item["finished_at"] = time.time()
                                ai_obj.setdefault("decision_trace", []).append(trace_item)
                                action = None
                                break
                            action = actionable[0]
                            break

                        if coverage_debt_open_count > 0:
                            replan_reason = "unresolved_high_risk_no_actionable_candidates"
                            replan_note = (
                                "coverage debt active with unresolved high-risk clusters; "
                                "replanning once with exclusions"
                            )
                            stop_reason = "unresolved_high_risk_no_actionable_candidates"
                        elif actionable_after_coverage and repeat_blocked and len(actionable_after_coverage) == len(repeat_blocked):
                            replan_reason = "all_candidates_blocked_repeat_policy"
                            replan_note = "all candidates blocked by repeat policy; replanning once with exclusions"
                            stop_reason = "all_candidates_blocked_repeat_policy"
                        else:
                            replan_reason = "all_candidates_already_covered"
                            replan_note = "all candidates already covered; replanning once with exclusions"
                            stop_reason = "all_candidates_already_covered"

                        if not replan_attempted:
                            replan_attempted = True
                            excluded_actions_for_replan = _covered_action_exclusions(sorted_candidates)
                            trace_item["replan"] = {
                                "attempted": True,
                                "reason": replan_reason,
                                "excluded_count": len(excluded_actions_for_replan),
                                "excluded": [_action_trace_view(a) for a in excluded_actions_for_replan],
                            }
                            note(
                                "llm_decision",
                                "planner",
                                replan_note,
                                agg=agg,
                            )
                            continue

                        if actions_executed == 0 and not ai_obj.get("actions"):
                            ai_obj["notes"] = "Planner proposed only baseline-completed web actions; stopping agentic loop."
                        if coverage_debt_open_count > 0:
                            trace_item["unresolved_high_risk_clusters"] = open_high_risk_clusters[:10]
                        trace_item["decision"] = {"result": "stop", "reason": stop_reason}
                        trace_item["finished_at"] = time.time()
                        ai_obj.setdefault("decision_trace", []).append(trace_item)
                        action = None
                        break

                    if action is None:
                        break

                    trace_item["selected_action"] = _action_trace_view(action)
                    rationale = _short_text(action.get("reasoning"))
                    hypothesis = _short_text(action.get("hypothesis"))
                    expected = _short_text(action.get("expected_evidence"))
                    decision_parts = [f"selected={_summarize_action_for_log(action)}"]
                    if rationale:
                        decision_parts.append(f"rationale={rationale}")
                    if hypothesis:
                        decision_parts.append(f"hypothesis={hypothesis}")
                    if expected:
                        decision_parts.append(f"expect={expected}")
                    note("llm_decision", action.get("tool", "planner"), " | ".join(decision_parts), agg=agg)

                    pre_findings_state = _findings_state_now()
                    pre_findings_count = int(pre_findings_state.get("total_count", 0))
                    pre_unique_findings_count = int(pre_findings_state.get("unique_all_count", 0))
                    pre_risk_classes = set(pre_findings_state.get("risk_classes", set()) or set())
                    pre_all_keys = set(pre_findings_state.get("all_keys", set()) or set())
                    pre_agentic_keys = set(pre_findings_state.get("agentic_keys", set()) or set())
                    pre_agentic_total = int(pre_findings_state.get("agentic_total", 0))
                    pre_open_high_risk_cluster_count = int(pre_findings_state.get("open_high_risk_cluster_count", 0))
                    pre_web_target_count = len(set(allowed_web_targets))

                    note("tool_start", action["tool"], f"Running {action['tool']} (agentic)", agg=agg)
                    started_at = time.time()
                    entry = run_agentic_action(action)
                    finished_at = time.time()
                    note("tool_end", action["tool"], f"Finished {action['tool']} (agentic)", agg=agg)

                    extra_results = entry.pop("_extra_results", None)
                    agg.setdefault("results", []).append(entry)
                    ai_obj["actions"].append(
                        {
                            "tool": action["tool"],
                            "target": entry.get("target"),
                            "profile": action.get("profile"),
                            "priority": action.get("priority"),
                            "reasoning": action.get("reasoning"),
                            "hypothesis": action.get("hypothesis"),
                            "expected_evidence": action.get("expected_evidence"),
                            "phase": "agentic",
                            "success": bool(entry.get("success")) if not entry.get("skipped") else False,
                            "skipped": bool(entry.get("skipped")),
                            "error": entry.get("error") or entry.get("reason"),
                            "reason": entry.get("reason"),
                            "started_at": started_at,
                            "finished_at": finished_at,
                        }
                    )

                    extra_added = 0
                    if isinstance(extra_results, list):
                        for extra in extra_results:
                            if not isinstance(extra, dict):
                                continue
                            agg.setdefault("results", []).append(extra)
                            ai_obj["actions"].append(
                                {
                                    "tool": extra.get("tool"),
                                    "target": extra.get("target"),
                                    "profile": extra.get("profile") or action.get("profile"),
                                    "reasoning": extra.get("reason") or "Fallback after gobuster failure",
                                    "phase": "agentic",
                                    "success": bool(extra.get("success")) if not extra.get("skipped") else False,
                                    "skipped": bool(extra.get("skipped")),
                                    "error": extra.get("error") or extra.get("reason"),
                                    "reason": extra.get("reason"),
                                    "started_at": extra.get("started_at", started_at),
                                    "finished_at": extra.get("finished_at", finished_at),
                                }
                            )
                            extra_added += 1

                    actions_executed += 1
                    _restrict_browser_use_result_scope(action, entry)
                    _validate_browser_discovery_urls(action, entry)
                    if action["tool"] == "httpx" and entry.get("success"):
                        alive = entry.get("data", {}).get("alive")
                        if isinstance(alive, list) and alive:
                            scoped_alive = self._scope_web_targets_for_target(
                                normalized,
                                [str(x).strip() for x in alive if str(x).strip()],
                                expand_web_scope=bool(url_target_expand_web_scope),
                            )
                            allowed_web_targets = [str(x) for x in scoped_alive if str(x).strip()]
                            web_targets = list(allowed_web_targets)
                            agg["web_targets"] = web_targets
                    if action["tool"] == "subfinder" and entry.get("success") and not lock_web_targets:
                        hosts = entry.get("data", {}).get("hosts")
                        if isinstance(hosts, list) and hosts:
                            promoted = self._promote_subfinder_hosts(scan_host, hosts)
                            promoted_urls = promoted.get("urls", []) if isinstance(promoted, dict) else []
                            promoted_urls = self._dedupe_web_targets_prefer_https(
                                [str(u).strip() for u in promoted_urls if isinstance(u, str) and str(u).strip()]
                            )
                            validated_urls: List[str] = []
                            validation_stats: Dict[str, Any] = {
                                "candidate_urls": len(promoted_urls),
                                "validation_attempted": False,
                                "validated_urls": 0,
                                "used_httpx": False,
                            }

                            subfinder_cfg = self._tool_config("subfinder")
                            try:
                                max_validation_targets = int(subfinder_cfg.get("max_validation_targets", 120))
                            except Exception:
                                max_validation_targets = 120
                            max_validation_targets = max(1, min(max_validation_targets, 500))
                            candidate_urls = promoted_urls[:max_validation_targets]

                            if candidate_urls and self._has_scanner("httpx") and self._tool_enabled("httpx", default=True):
                                validation_stats["validation_attempted"] = True
                                validation_stats["used_httpx"] = True
                                validation_started = time.time()
                                note(
                                    "tool_start",
                                    "httpx",
                                    f"Validating {len(candidate_urls)} subfinder-promoted URL(s) with httpx",
                                    agg=agg,
                                )
                                validation_entry = self._run_tool(
                                    "httpx",
                                    lambda: self.scanners["httpx"].scan(
                                        candidate_urls,
                                        cancel_event=cancel_event,
                                        timeout_seconds=self._tool_timeout_seconds("httpx"),
                                    ),
                                )
                                validation_finished = time.time()
                                note("tool_end", "httpx", "Finished subfinder promotion validation", agg=agg)
                                validation_entry["phase"] = "agentic"
                                validation_entry["target"] = scan_host
                                validation_entry["profile"] = action.get("profile")
                                validation_entry["target_scope"] = "subfinder_promotion_validation"
                                validation_entry["reason"] = "Validate subfinder-promoted URLs before expansion"
                                agg.setdefault("results", []).append(validation_entry)
                                ai_obj["actions"].append(
                                    {
                                        "tool": "httpx",
                                        "target": scan_host,
                                        "profile": action.get("profile"),
                                        "reasoning": "Validate promoted subdomains before promoting to web targets.",
                                        "phase": "agentic",
                                        "success": bool(validation_entry.get("success"))
                                        if not validation_entry.get("skipped")
                                        else False,
                                        "skipped": bool(validation_entry.get("skipped")),
                                        "error": validation_entry.get("error") or validation_entry.get("reason"),
                                        "reason": validation_entry.get("reason"),
                                        "started_at": validation_started,
                                        "finished_at": validation_finished,
                                    }
                                )
                                extra_added += 1
                                if validation_entry.get("success"):
                                    alive = validation_entry.get("data", {}).get("alive")
                                    if isinstance(alive, list):
                                        validated_urls = self._dedupe_web_targets_prefer_https(
                                            [str(u).strip() for u in alive if isinstance(u, str) and str(u).strip()]
                                        )
                                        for u in validated_urls:
                                            agentic_success.add(("httpx", u))
                            else:
                                validated_urls = candidate_urls

                            validation_stats["validated_urls"] = len(validated_urls)
                            for u in validated_urls:
                                if u not in allowed_web_targets:
                                    allowed_web_targets.append(u)
                                    web_targets.append(u)
                            allowed_web_targets = self._scope_web_targets_for_target(
                                normalized,
                                allowed_web_targets,
                                expand_web_scope=bool(url_target_expand_web_scope),
                            )
                            web_targets = list(allowed_web_targets)
                            if isinstance(entry.get("data"), dict):
                                entry["data"]["promoted_urls"] = [str(u) for u in promoted_urls if str(u).strip()]
                                entry["data"]["validated_urls"] = [str(u) for u in validated_urls if str(u).strip()]
                                entry["data"]["promotion_stats"] = (
                                    promoted.get("stats", {}) if isinstance(promoted, dict) else {}
                                )
                                entry["data"]["validation_stats"] = validation_stats
                            stats = promoted.get("stats", {}) if isinstance(promoted.get("stats"), dict) else {}
                            if stats:
                                agg.setdefault("summary_notes", []).append(
                                    (
                                        "Subdomain expansion (agentic): discovered "
                                        f"{int(stats.get('discovered', 0))}, in-scope {int(stats.get('in_scope', 0))}, "
                                        f"resolved {int(stats.get('resolved', 0))}, promoted {int(stats.get('promoted_hosts', 0))} host(s), "
                                        f"validated URLs {int(validation_stats.get('validated_urls', 0))}."
                                    )
                                )
                            agg["web_targets"] = web_targets

                    post_findings_state = _findings_state_now()
                    post_findings_count = int(post_findings_state.get("total_count", 0))
                    post_unique_findings_count = int(post_findings_state.get("unique_all_count", 0))
                    post_risk_classes = set(post_findings_state.get("risk_classes", set()) or set())
                    post_agentic_keys = set(post_findings_state.get("agentic_keys", set()) or set())
                    post_agentic_total = int(post_findings_state.get("agentic_total", 0))
                    post_open_high_risk_cluster_count = int(post_findings_state.get("open_high_risk_cluster_count", 0))
                    new_risk_classes = sorted(post_risk_classes - pre_risk_classes)
                    risk_class_delta = len(new_risk_classes)
                    post_web_target_count = len(set(allowed_web_targets))
                    findings_delta = max(0, post_findings_count - pre_findings_count)
                    unique_findings_delta = max(0, post_unique_findings_count - pre_unique_findings_count)
                    agentic_findings_delta = max(0, post_agentic_total - pre_agentic_total)
                    agentic_unique_findings_delta = max(0, len(post_agentic_keys) - len(pre_agentic_keys))
                    new_agentic_keys = post_agentic_keys - pre_agentic_keys
                    agentic_net_new_unique_delta = len(new_agentic_keys - pre_all_keys)
                    agentic_reconfirmed_unique_delta = len(new_agentic_keys & pre_all_keys)
                    post_items = post_findings_state.get("items", []) if isinstance(post_findings_state, dict) else []
                    post_items_by_key: Dict[str, Dict[str, Any]] = {}
                    for row in post_items if isinstance(post_items, list) else []:
                        if not isinstance(row, dict):
                            continue
                        key = str(row.get("dedup_key") or "").strip()
                        if not key:
                            key = self._finding_dedup_key(row)
                        if key and key not in post_items_by_key:
                            post_items_by_key[key] = row
                    new_agentic_items = [
                        post_items_by_key[k]
                        for k in new_agentic_keys
                        if k in post_items_by_key and isinstance(post_items_by_key.get(k), dict)
                    ]
                    browser_discovery_unique_delta = 0
                    browser_observation_unique_delta = 0
                    browser_security_unique_delta = 0
                    for row in new_agentic_items:
                        tool_name = str(row.get("tool") or "").strip().lower()
                        if tool_name != "browser_use":
                            continue
                        finding_type = str(row.get("type") or "").strip().lower()
                        sev_rank = int(self._severity_rank(row.get("severity") or "INFO"))
                        if finding_type == "browser_discovery":
                            browser_discovery_unique_delta += 1
                        else:
                            browser_observation_unique_delta += 1
                            if sev_rank >= 3:
                                browser_security_unique_delta += 1
                    open_high_risk_cluster_delta = max(
                        0, pre_open_high_risk_cluster_count - post_open_high_risk_cluster_count
                    )
                    web_target_delta = max(0, post_web_target_count - pre_web_target_count)
                    status = "skipped" if entry.get("skipped") else ("success" if entry.get("success") else "failed")
                    if status == "success" and (
                        risk_class_delta > 0
                        or web_target_delta > 0
                        or agentic_net_new_unique_delta > 0
                        or open_high_risk_cluster_delta > 0
                        or extra_added > 0
                    ):
                        signal = "high"
                        signal_note = "Action produced net-new risk/coverage signal."
                    elif status == "success" and (
                        agentic_unique_findings_delta > 0
                        or agentic_reconfirmed_unique_delta > 0
                        or findings_delta > 0
                    ):
                        signal = "medium"
                        signal_note = "Action added or reconfirmed findings, but with limited net-new risk classes."
                    elif status == "success":
                        signal = "medium"
                        signal_note = "Action succeeded but added limited net-new signal."
                    elif status == "failed":
                        signal = "low"
                        signal_note = "Action failed; planner should pivot based on error context."
                    else:
                        signal = "low"
                        signal_note = "Action was skipped due to coverage/scope constraints."

                    gain_score = (
                        int(risk_class_delta) * 4
                        + int(agentic_net_new_unique_delta) * 3
                        + int(open_high_risk_cluster_delta) * 4
                        + int(web_target_delta) * 2
                        + (1 if int(extra_added) > 0 else 0)
                    )
                    if int(agentic_reconfirmed_unique_delta) > 0:
                        gain_score += 1
                    if status != "success":
                        gain_score -= 1

                    chosen_tool = str(action.get("tool") or "").strip().lower()
                    chosen_target = str(entry.get("target") or "").strip()
                    browser_fallback_mode = ""
                    browser_focus_hits = 0
                    browser_fallback_confidence = ""
                    browser_focused_endpoint_artifacts = 0
                    browser_discovery_validated_urls: Set[str] = set()
                    browser_discovery_validation_attempted = False
                    browser_discovery_validation_success = False
                    if chosen_tool == "browser_use":
                        data_block = entry.get("data") if isinstance(entry.get("data"), dict) else {}
                        observation = data_block.get("observation") if isinstance(data_block.get("observation"), dict) else {}
                        browser_fallback_mode = str(observation.get("fallback_mode") or "").strip().lower()
                        try:
                            browser_focus_hits = int(observation.get("focus_hits") or 0)
                        except Exception:
                            browser_focus_hits = 0
                        try:
                            browser_focused_endpoint_artifacts = int(observation.get("focused_endpoint_artifacts") or 0)
                        except Exception:
                            browser_focused_endpoint_artifacts = 0
                        browser_fallback_confidence = str(observation.get("fallback_confidence") or "").strip().lower()
                        validation_block = (
                            data_block.get("browser_discovery_validation")
                            if isinstance(data_block.get("browser_discovery_validation"), dict)
                            else {}
                        )
                        browser_discovery_validation_attempted = bool(validation_block.get("attempted"))
                        browser_discovery_validation_success = bool(validation_block.get("httpx_success"))
                        validated_urls_raw = (
                            validation_block.get("validated_urls")
                            if isinstance(validation_block.get("validated_urls"), list)
                            else []
                        )
                        browser_discovery_validated_urls = {
                            str(u).strip() for u in validated_urls_raw if isinstance(u, str) and str(u).strip()
                        }
                    browser_validated_discovery_unique_delta = 0
                    browser_unvalidated_discovery_unique_delta = 0
                    if chosen_tool == "browser_use" and new_agentic_items:
                        for row in new_agentic_items:
                            if not isinstance(row, dict):
                                continue
                            if str(row.get("tool") or "").strip().lower() != "browser_use":
                                continue
                            if str(row.get("type") or "").strip().lower() != "browser_discovery":
                                continue
                            ev = str(row.get("evidence") or "").strip()
                            if ev and ev in browser_discovery_validated_urls:
                                browser_validated_discovery_unique_delta += 1
                            else:
                                browser_unvalidated_discovery_unique_delta += 1
                    if chosen_tool == "browser_use" and browser_unvalidated_discovery_unique_delta > 0:
                        # Discovery-only URLs should not earn gain until a status check (httpx) confirms reachability.
                        gain_score -= int(browser_unvalidated_discovery_unique_delta) * 3
                        if browser_observation_unique_delta <= 0 and open_high_risk_cluster_delta <= 0:
                            gain_score = min(gain_score, 0)

                    if chosen_tool == "browser_use":
                        completed = bool(data_block.get("completed"))
                        if browser_discovery_unique_delta > 0 and open_high_risk_cluster_delta <= 0:
                            # Browser-discovery endpoint churn is useful for scope expansion but should not dominate
                            # gain when it does not reduce unresolved high-risk coverage debt.
                            gain_score -= min(8, int(browser_validated_discovery_unique_delta))
                        if (
                            browser_discovery_unique_delta > 0
                            and browser_observation_unique_delta <= 0
                            and open_high_risk_cluster_delta <= 0
                        ):
                            gain_score = min(gain_score, 0)
                            if chosen_target:
                                browser_use_fallback_block_targets.add(chosen_target)
                        if browser_fallback_mode:
                            fallback_penalty = 0
                            if not completed:
                                fallback_penalty += 3
                            if browser_fallback_confidence == "low":
                                fallback_penalty += 3
                            if browser_focus_hits <= 0:
                                fallback_penalty += 2
                            if fallback_penalty > 0:
                                gain_score -= int(fallback_penalty)
                            if not completed or browser_fallback_confidence == "low":
                                # Down-rank incomplete/low-confidence fallback browser runs regardless
                                # of focus hits so they don't dominate gain scoring.
                                fallback_gain_cap = 2
                                if (
                                    browser_observation_unique_delta > 0
                                    and browser_focused_endpoint_artifacts > 0
                                    and open_high_risk_cluster_delta > 0
                                ):
                                    fallback_gain_cap = 8
                                elif browser_observation_unique_delta > 0:
                                    fallback_gain_cap = 4
                                gain_score = min(gain_score, int(fallback_gain_cap))
                            if (not completed or browser_fallback_confidence == "low") and open_high_risk_cluster_delta <= 0:
                                gain_score = min(gain_score, 0)
                                if chosen_target:
                                    browser_use_fallback_block_targets.add(chosen_target)
                        if (
                            browser_unvalidated_discovery_unique_delta > 0
                            and browser_observation_unique_delta <= 0
                            and browser_security_unique_delta <= 0
                            and open_high_risk_cluster_delta <= 0
                        ):
                            signal = "low"
                            signal_note = (
                                "Browser action produced unvalidated discovery-only URLs; "
                                "httpx validation is required before treating these as meaningful signal."
                            )
                        if browser_focus_hits > 0 and browser_focused_endpoint_artifacts <= 0 and status == "success":
                            signal_note = (
                                "Browser action found focus URLs but lacked concrete endpoint artifacts; "
                                "prefer non-browser pivots next."
                            )
                        if browser_security_unique_delta > 0 and open_high_risk_cluster_delta <= 0:
                            signal = "high"
                            signal_note = "Browser action produced net-new security observations."
                        if browser_fallback_mode and (not completed or browser_fallback_confidence == "low"):
                            signal = "medium" if browser_observation_unique_delta > 0 else "low"
                            signal_note = (
                                "Fallback browser evidence was incomplete/low-confidence; "
                                "deprioritizing repeated actions on same target unless independently validated."
                            )

                    # Track per-tool/target execution pressure and recent signal trend.
                    action_repeat_key = _action_repeat_key(action, entry)
                    if chosen_tool:
                        agentic_tool_counts[chosen_tool] = int(agentic_tool_counts.get(chosen_tool, 0)) + 1
                    if chosen_target:
                        agentic_target_counts[chosen_target] = int(agentic_target_counts.get(chosen_target, 0)) + 1
                    if action_repeat_key:
                        agentic_action_counts[action_repeat_key] = int(agentic_action_counts.get(action_repeat_key, 0)) + 1
                    if chosen_tool:
                        agentic_tool_gain_scores.setdefault(chosen_tool, []).append(int(gain_score))
                        if len(agentic_tool_gain_scores.get(chosen_tool, [])) > 6:
                            agentic_tool_gain_scores[chosen_tool] = agentic_tool_gain_scores[chosen_tool][-6:]
                    recent_gain_scores.append(int(gain_score))
                    if len(recent_gain_scores) > 8:
                        recent_gain_scores = recent_gain_scores[-8:]
                    if risk_class_delta > 0 and chosen_tool:
                        agentic_tool_risk_gain_counts[chosen_tool] = (
                            int(agentic_tool_risk_gain_counts.get(chosen_tool, 0)) + 1
                        )
                        agentic_tool_no_risk_gain_counts[chosen_tool] = 0
                    elif chosen_tool:
                        agentic_tool_no_risk_gain_counts[chosen_tool] = (
                            int(agentic_tool_no_risk_gain_counts.get(chosen_tool, 0)) + 1
                        )
                    if gain_score > 0:
                        low_signal_streak = 0
                    else:
                        low_signal_streak = int(low_signal_streak) + 1
                        if chosen_tool:
                            agentic_low_signal_tool_counts[chosen_tool] = (
                                int(agentic_low_signal_tool_counts.get(chosen_tool, 0)) + 1
                            )
                    if baseline_broad_nuclei_targets:
                        if gain_score <= 0:
                            nonpositive_after_broad_streak = int(nonpositive_after_broad_streak) + 1
                        else:
                            nonpositive_after_broad_streak = 0
                    ledger_entry = {
                        "iteration": int(trace_item.get("iteration") or 0),
                        "phase": "agentic",
                        "tool": chosen_tool,
                        "target": chosen_target,
                        "status": status,
                        "reason": str(entry.get("reason") or "").strip(),
                        "error": str(entry.get("error") or "").strip(),
                        "findings_delta": int(findings_delta),
                        "unique_findings_delta": int(unique_findings_delta),
                        "agentic_findings_delta": int(agentic_findings_delta),
                        "agentic_unique_findings_delta": int(agentic_unique_findings_delta),
                        "agentic_net_new_unique_delta": int(agentic_net_new_unique_delta),
                        "agentic_reconfirmed_unique_delta": int(agentic_reconfirmed_unique_delta),
                        "risk_class_delta": int(risk_class_delta),
                        "open_high_risk_cluster_delta": int(open_high_risk_cluster_delta),
                        "web_target_delta": int(web_target_delta),
                        "extra_results": int(extra_added),
                        "gain_score": int(gain_score),
                        "browser_fallback_mode": browser_fallback_mode,
                        "browser_focus_hits": int(browser_focus_hits),
                        "browser_focused_endpoint_artifacts": int(browser_focused_endpoint_artifacts),
                        "browser_fallback_confidence": browser_fallback_confidence,
                        "browser_discovery_unique_delta": int(browser_discovery_unique_delta),
                        "browser_validated_discovery_unique_delta": int(browser_validated_discovery_unique_delta),
                        "browser_unvalidated_discovery_unique_delta": int(browser_unvalidated_discovery_unique_delta),
                        "browser_observation_unique_delta": int(browser_observation_unique_delta),
                        "browser_security_unique_delta": int(browser_security_unique_delta),
                        "browser_discovery_validation_attempted": bool(browser_discovery_validation_attempted),
                        "browser_discovery_validation_success": bool(browser_discovery_validation_success),
                        "started_at": started_at,
                        "finished_at": finished_at,
                    }
                    planner_action_ledger.append(ledger_entry)
                    if len(planner_action_ledger) > 500:
                        planner_action_ledger = planner_action_ledger[-500:]
                    agg["agentic_action_ledger"] = [dict(x) for x in planner_action_ledger]

                    trace_item["outcome"] = {
                        "status": status,
                        "tool_result_reason": entry.get("reason"),
                        "tool_result_error": entry.get("error"),
                        "extra_results_added": int(extra_added),
                        "findings_count_before": int(pre_findings_count),
                        "findings_count_after": int(post_findings_count),
                        "findings_count_delta": int(findings_delta),
                        "unique_findings_count_before": int(pre_unique_findings_count),
                        "unique_findings_count_after": int(post_unique_findings_count),
                        "unique_findings_count_delta": int(unique_findings_delta),
                        "agentic_findings_count_before": int(pre_agentic_total),
                        "agentic_findings_count_after": int(post_agentic_total),
                        "agentic_findings_count_delta": int(agentic_findings_delta),
                        "agentic_unique_findings_count_before": int(len(pre_agentic_keys)),
                        "agentic_unique_findings_count_after": int(len(post_agentic_keys)),
                        "agentic_unique_findings_count_delta": int(agentic_unique_findings_delta),
                        "agentic_net_new_unique_delta": int(agentic_net_new_unique_delta),
                        "agentic_reconfirmed_unique_delta": int(agentic_reconfirmed_unique_delta),
                        "risk_class_count_before": int(len(pre_risk_classes)),
                        "risk_class_count_after": int(len(post_risk_classes)),
                        "risk_class_delta": int(risk_class_delta),
                        "new_risk_classes": new_risk_classes[:12],
                        "open_high_risk_cluster_count_before": int(pre_open_high_risk_cluster_count),
                        "open_high_risk_cluster_count_after": int(post_open_high_risk_cluster_count),
                        "open_high_risk_cluster_delta": int(open_high_risk_cluster_delta),
                        "web_target_count_before": int(pre_web_target_count),
                        "web_target_count_after": int(post_web_target_count),
                        "web_target_count_delta": int(web_target_delta),
                        "gain_score": int(gain_score),
                        "low_signal_streak_after": int(low_signal_streak),
                        "nonpositive_after_broad_streak_after": int(nonpositive_after_broad_streak),
                        "tool_usage_count": int(agentic_tool_counts.get(chosen_tool, 0)),
                        "target_usage_count": int(agentic_target_counts.get(chosen_target, 0)),
                        "tool_target_usage_count": int(agentic_action_counts.get(action_repeat_key, 0))
                        if action_repeat_key
                        else 0,
                        "tool_low_signal_count": int(agentic_low_signal_tool_counts.get(chosen_tool, 0)),
                        "browser_fallback_mode": browser_fallback_mode,
                        "browser_focus_hits": int(browser_focus_hits),
                        "browser_focused_endpoint_artifacts": int(browser_focused_endpoint_artifacts),
                        "browser_fallback_confidence": browser_fallback_confidence,
                        "browser_discovery_unique_delta": int(browser_discovery_unique_delta),
                        "browser_validated_discovery_unique_delta": int(browser_validated_discovery_unique_delta),
                        "browser_unvalidated_discovery_unique_delta": int(browser_unvalidated_discovery_unique_delta),
                        "browser_observation_unique_delta": int(browser_observation_unique_delta),
                        "browser_security_unique_delta": int(browser_security_unique_delta),
                        "browser_discovery_validation_attempted": bool(browser_discovery_validation_attempted),
                        "browser_discovery_validation_success": bool(browser_discovery_validation_success),
                    }
                    trace_item["critique"] = {
                        "signal": signal,
                        "summary": signal_note,
                    }
                    note(
                        "llm_critique",
                        action.get("tool", "planner"),
                        (
                            f"signal={signal}; status={status}; findings_delta={int(findings_delta)}; "
                            f"unique_findings_delta={int(unique_findings_delta)}; "
                            f"agentic_unique_delta={int(agentic_unique_findings_delta)}; "
                            f"net_new_unique_delta={int(agentic_net_new_unique_delta)}; "
                            f"reconfirmed_unique_delta={int(agentic_reconfirmed_unique_delta)}; "
                            f"risk_classes_delta={int(risk_class_delta)}; web_targets_delta={int(web_target_delta)}; "
                            f"open_high_risk_delta={int(open_high_risk_cluster_delta)}; "
                            f"extra_results={int(extra_added)}; gain_score={int(gain_score)}"
                        ),
                        agg=agg,
                    )
                    trace_item["decision"] = {"result": "executed"}
                    if stop_requested:
                        trace_item["decision"]["stop_after_execution"] = True
                    trace_item["finished_at"] = time.time()
                    ai_obj.setdefault("decision_trace", []).append(trace_item)
                    if stop_requested:
                        break

        # Recompute summary/findings on the combined results.
        agg["finished_at"] = time.time()
        agg["results"] = stable_sort_results(agg.get("results", []) or [])

        ffuf_fallback_hits: List[Tuple[str, int]] = []
        ffuf_agentic_hits: List[Tuple[str, int]] = []
        for entry in agg.get("results", []) or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("tool") != "ffuf":
                continue
            if entry.get("phase") != "agentic":
                continue
            if not entry.get("success"):
                continue
            findings = entry.get("data", {}).get("findings")
            count = len(findings) if isinstance(findings, list) else 0
            target = str(entry.get("target") or "").strip() or "unknown-target"
            if entry.get("fallback_for") == "gobuster":
                ffuf_fallback_hits.append((target, count))
            else:
                ffuf_agentic_hits.append((target, count))
        if ffuf_fallback_hits:
            total = sum(n for _, n in ffuf_fallback_hits)
            targets = ", ".join(f"{t} ({n})" for t, n in ffuf_fallback_hits[:3])
            if len(ffuf_fallback_hits) > 3:
                targets = f"{targets}, ..."
            summary_note = (
                "ffuf fallback (after gobuster failure) ran and found "
                f"{total} paths across {len(ffuf_fallback_hits)} target(s): {targets}."
            )
            agg.setdefault("summary_notes", []).append(summary_note)
        if ffuf_agentic_hits:
            total = sum(n for _, n in ffuf_agentic_hits)
            targets = ", ".join(f"{t} ({n})" for t, n in ffuf_agentic_hits[:3])
            if len(ffuf_agentic_hits) > 3:
                targets = f"{targets}, ..."
            summary_note = (
                "agentic ffuf action(s) ran and found "
                f"{total} paths across {len(ffuf_agentic_hits)} target(s): {targets}."
            )
            agg.setdefault("summary_notes", []).append(summary_note)
        if int(coverage_debt_pivot_count) > 0:
            agg.setdefault("summary_notes", []).append(
                (
                    "Coverage-debt fallback pivot used "
                    f"{int(coverage_debt_pivot_count)} time(s) to avoid repeat-blocked high-risk action loops."
                )
            )

        findings_for_state = self._collect_findings(agg)
        if not isinstance(findings_for_state, list):
            findings_for_state = []
        cluster_state = _cluster_findings_for_planner(findings_for_state)
        agg["finding_cluster_overview"] = {
            "total_findings": int(cluster_state.get("total_findings", 0)),
            "cluster_count": int(cluster_state.get("cluster_count", 0)),
            "open_high_risk_cluster_count": len(cluster_state.get("open_high_risk_clusters", []) or []),
            "covered_cluster_count": len(cluster_state.get("covered_cluster_ids", []) or []),
        }
        agg["finding_clusters"] = cluster_state.get("clusters", [])
        unresolved_high_risk_clusters = [
            c for c in (cluster_state.get("open_high_risk_clusters", []) or []) if isinstance(c, dict)
        ]
        agg["unresolved_high_risk_clusters"] = unresolved_high_risk_clusters[:50]
        if unresolved_high_risk_clusters:
            sample_titles = ", ".join(
                str(c.get("title") or "cluster").strip() for c in unresolved_high_risk_clusters[:3] if str(c.get("title") or "").strip()
            )
            if len(unresolved_high_risk_clusters) > 3:
                sample_titles = f"{sample_titles}, ..."
            agg.setdefault("summary_notes", []).append(
                (
                    "Unresolved high-risk clusters remain after agentic phase: "
                    f"{len(unresolved_high_risk_clusters)}"
                    + (f" ({sample_titles})" if sample_titles else "")
                    + "."
                )
            )
        agg["baseline_action_ledger"] = _baseline_action_ledger()
        if planner_action_ledger:
            agg["agentic_action_ledger"] = [dict(x) for x in planner_action_ledger]

        baseline_keys: Set[str] = set()
        agentic_keys: Set[str] = set()
        baseline_total = 0
        agentic_total = 0
        for f in findings_for_state:
            if not isinstance(f, dict):
                continue
            phase = str(f.get("phase") or "baseline").strip().lower() or "baseline"
            dedup_key = str(f.get("dedup_key") or "").strip()
            if not dedup_key:
                dedup_key = self._finding_dedup_key(f)
            if phase == "agentic":
                agentic_total += 1
                if dedup_key:
                    agentic_keys.add(dedup_key)
            else:
                baseline_total += 1
                if dedup_key:
                    baseline_keys.add(dedup_key)
        agentic_delta = {
            "baseline_total_findings": int(baseline_total),
            "agentic_total_findings": int(agentic_total),
            "baseline_unique_findings": len(baseline_keys),
            "agentic_unique_findings": len(agentic_keys),
            "agentic_net_new_unique_findings": len(agentic_keys - baseline_keys),
            "agentic_reconfirmed_unique_findings": len(agentic_keys & baseline_keys),
            "agentic_duplicate_only_findings": max(0, int(agentic_total) - int(len(agentic_keys))),
        }
        agg["agentic_delta"] = agentic_delta
        reconfirmed_only = bool(
            int(agentic_delta.get("agentic_unique_findings", 0)) > 0
            and int(agentic_delta.get("agentic_net_new_unique_findings", 0)) == 0
        )
        reconfirmed_note = " (reconfirmed existing signatures only)" if reconfirmed_only else ""
        agg.setdefault("summary_notes", []).append(
            (
                "Agentic phase delta: "
                f"{int(agentic_delta.get('agentic_total_findings', 0))} finding(s), "
                f"{int(agentic_delta.get('agentic_unique_findings', 0))} unique signatures, "
                f"net-new unique {int(agentic_delta.get('agentic_net_new_unique_findings', 0))}, "
                f"reconfirmed unique {int(agentic_delta.get('agentic_reconfirmed_unique_findings', 0))}, "
                f"duplicate-only findings {int(agentic_delta.get('agentic_duplicate_only_findings', 0))}."
                f"{reconfirmed_note}"
            )
        )

        # Label LLM status for visibility
        if not llm_enabled:
            agg["llm"] = {"enabled": False, "reason": "Disabled by config or --no-llm", "calls": []}

        findings = self._collect_findings(agg)
        if llm_enabled:
            note("llm_start", "summary", "Summarizing with LLM", agg=agg)
            ctx = self._build_llm_summary_context(agg, findings)
            summary, llm_meta = self._summarize_with_llm(agg, context=ctx)
            if llm_meta:
                self._append_llm_call(agg, llm_meta)
                if llm_meta.get("error"):
                    note("llm_error", "summary", f"LLM summary failed: {llm_meta['error']}", agg=agg)
            if summary:
                agg["summary"] = summary

        findings = self._apply_remediations(
            agg,
            findings,
            enabled=remediate and llm_enabled,
            max_remediations=max_remediations,
            min_severity=min_remediation_severity,
        )
        findings = self._apply_compliance_tags(agg, findings, normalized_compliance)
        agg["findings"] = findings
        normalized_summary, summary_meta = normalize_report_summary(
            agg.get("summary"),
            findings if isinstance(findings, list) else [],
            finding_clusters=agg.get("finding_clusters") if isinstance(agg.get("finding_clusters"), list) else None,
        )
        if isinstance(normalized_summary, dict):
            agg["summary"] = normalized_summary
        if isinstance(summary_meta, dict) and summary_meta:
            agg["summary_normalization"] = summary_meta
        else:
            agg.pop("summary_normalization", None)
        try:
            agg["finding_metrics"] = self._build_finding_metrics(findings if isinstance(findings, list) else [])
        except Exception:
            pass
        try:
            summary_findings = []
            summary = agg.get("summary")
            if isinstance(summary, dict):
                sf = summary.get("findings")
                if isinstance(sf, list):
                    summary_findings = sf
            agg["recommended_next_actions"] = build_recommended_next_actions(
                summary_findings,
                findings if isinstance(findings, list) else [],
                normalized_compliance,
            )
        except Exception:
            pass
        if isinstance(normalized_compliance, str) and normalized_compliance.strip():
            try:
                agg["compliance_coverage_matrix"] = build_compliance_coverage_matrix(agg)
            except Exception:
                pass

        try:
            annotate_schema_validation(agg, kind="audit")
        except Exception:
            pass

        if output is not None:
            self._write_evidence_pack(agg, output)
            replay_meta = self._write_replay_trace(agg, output)
            if isinstance(replay_meta, dict):
                agg["replay_trace"] = replay_meta
                ai_meta = agg.get("ai_audit")
                if isinstance(ai_meta, dict):
                    ai_meta["replay_trace_file"] = replay_meta.get("file")
                    ai_meta["replay_trace_version"] = replay_meta.get("version")
            llm_trace_meta = self._write_llm_reasoning_trace(agg, output)
            if isinstance(llm_trace_meta, dict):
                agg["llm_reasoning_trace"] = llm_trace_meta
                ai_meta = agg.get("ai_audit")
                if isinstance(ai_meta, dict):
                    ai_meta["llm_reasoning_json_file"] = llm_trace_meta.get("json_file")
                    ai_meta["llm_reasoning_markdown_file"] = llm_trace_meta.get("markdown_file")
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                with open(output, "w") as f:
                    json.dump(agg, f, indent=2)
                agg["saved_to"] = str(output)
            except Exception as e:
                agg["saved_to"] = None
                agg["write_error"] = str(e)
        else:
            agg["saved_to"] = None

        if run_error:
            agg["run_error"] = run_error

        return agg
