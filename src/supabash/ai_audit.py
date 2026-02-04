from __future__ import annotations

import json
import time
from pathlib import Path
from threading import Event
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from supabash.audit import AuditOrchestrator
from supabash.agent import MethodologyPlanner
from supabash import prompts
from supabash.llm import ToolCallingNotSupported, ToolCallingError
from supabash.llm_context import prepare_json_payload
from supabash.report_order import stable_sort_results
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

        # Even when the user passes a URL, nmap can discover additional HTTP(S) ports.
        # Merge derived web targets so the agentic expansion can cover them.
        try:
            scan_host = str(agg.get("scan_host") or target).strip()
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
        agg["web_targets"] = web_targets

        baseline_web = web_targets[0] if web_targets else None
        extra_web_targets = [u for u in web_targets if u != baseline_web]

        if extra_web_targets:
            ai_obj["notes"] = f"Additional web targets detected: {', '.join(extra_web_targets[:6])}"

        # Agentic tool-calling phase (bounded).
        agentic_enabled = bool(llm_plan)
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
            try:
                for entry in agg.get("results", []) or []:
                    if isinstance(entry, dict) and entry.get("tool") == "nmap" and entry.get("success"):
                        scan_data = entry.get("data", {}).get("scan_data", {}) if isinstance(entry.get("data"), dict) else {}
                        open_ports = self._open_ports_from_nmap(scan_data if isinstance(scan_data, dict) else {})
                        break
            except Exception:
                open_ports = []

            tls_ports = [p for p in open_ports if p in (443, 8443)]
            smb_ports = [p for p in open_ports if p in (139, 445)]

            allowed_web_targets = [u for u in web_targets if isinstance(u, str) and u.strip()]
            sqlmap_targets = [u for u in allowed_web_targets if "?" in u]
            if normalized.get("sqlmap_url") and normalized["sqlmap_url"] not in sqlmap_targets:
                sqlmap_targets.insert(0, normalized["sqlmap_url"])

            tool_specs = {
                "httpx": {"target_kind": "web", "enabled_default": True},
                "whatweb": {"target_kind": "web", "enabled_default": True},
                "nuclei": {"target_kind": "web", "enabled_default": True},
                "gobuster": {"target_kind": "web", "enabled_default": True},
                "ffuf": {"target_kind": "web", "enabled_default": False},
                "katana": {"target_kind": "web", "enabled_default": False},
                "nikto": {"target_kind": "web", "enabled_default": False, "opt_in": bool(run_nikto)},
                "sqlmap": {"target_kind": "web", "enabled_default": True, "requires_param": True},
                "dnsenum": {"target_kind": "domain", "enabled_default": True},
                "subfinder": {"target_kind": "domain", "enabled_default": False},
                "sslscan": {"target_kind": "host_port", "enabled_default": True},
                "enum4linux-ng": {"target_kind": "host", "enabled_default": True, "requires_smb": True},
                "trivy": {"target_kind": "container", "enabled_default": True},
            }

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
                if tool == "sqlmap" and not sqlmap_targets:
                    continue
                if tool == "sslscan" and not tls_ports:
                    continue
                if tool == "enum4linux-ng" and not smb_ports:
                    continue
                if tool == "trivy" and not container_image:
                    continue
                allowed_tools.append(tool)

            baseline_success: set[tuple] = set()
            for entry in agg.get("results", []) or []:
                if not isinstance(entry, dict) or not entry.get("success"):
                    continue
                tool = entry.get("tool")
                if tool_specs.get(tool, {}).get("target_kind") != "web":
                    continue
                if tool == "httpx":
                    alive = entry.get("data", {}).get("alive")
                    if isinstance(alive, list):
                        for u in alive:
                            u = str(u).strip()
                            if u:
                                baseline_success.add((tool, u))
                target = entry.get("target")
                if isinstance(target, str) and target.strip():
                    baseline_success.add((tool, target.strip()))

            if not allowed_tools:
                ai_obj["planner"]["warning"] = "No eligible tools available for agentic phase."
                ai_obj["agentic_skipped"] = True
            else:
                allowed_argument_keys = {"profile", "target", "port", "rate_limit", "threads", "wordlist"}

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
                                                    },
                                                    "required": ["profile"],
                                                    "additionalProperties": False,
                                                },
                                                "reasoning": {"type": "string"},
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
                    reasoning = str(item.get("reasoning") or "").strip()
                    return {
                        "tool": tool,
                        "arguments": filtered,
                        "profile": profile,
                        "reasoning": reasoning,
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

                def plan_actions(remaining: int) -> Dict[str, Any]:
                    results_summary = []
                    for r in agg.get("results", []) or []:
                        if not isinstance(r, dict):
                            continue
                        results_summary.append(
                            {
                                "tool": r.get("tool"),
                                "success": r.get("success"),
                                "skipped": r.get("skipped"),
                                "phase": r.get("phase"),
                            }
                        )

                    findings_preview = []
                    try:
                        findings_preview = self._collect_findings(agg)[-20:]
                    except Exception:
                        findings_preview = []

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

                    context_obj = {
                        "target": target,
                        "mode": mode,
                        "remaining_actions": int(remaining),
                        "allowed_tools": allowed_tools,
                        "allowed_targets": {
                            "web": allowed_web_targets[:12],
                            "sqlmap": sqlmap_targets[:6],
                            "scan_host": scan_host,
                        },
                        "open_ports": open_ports,
                        "observations": {
                            "web_targets": allowed_web_targets[:12],
                            "results": results_summary[-12:],
                            "findings": findings_preview,
                        },
                        "compliance": compliance_block,
                        "constraints": {
                            "profile_enum": list(profile_values),
                            "sqlmap_requires_parameterized_url": True,
                            "nikto_opt_in": bool(run_nikto),
                            "trivy_requires_container": bool(container_image),
                            "tls_ports_detected": tls_ports,
                            "smb_ports_detected": bool(smb_ports),
                        },
                    }

                    max_chars = self._llm_max_chars(default=8000)
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

                    action_target = None
                    action_port = None

                    if canceled():
                        entry = {"tool": tool, "success": False, "skipped": True, "reason": "Canceled"}
                    elif tool_specs.get(tool, {}).get("target_kind") == "web":
                        action_target = target
                        action_key = (tool, action_target or "")
                        if not target:
                            entry = self._skip_tool(tool, "Missing target")
                        elif target not in allowed_web_targets and (tool != "sqlmap" or target not in sqlmap_targets):
                            entry = self._skip_tool(tool, "Target not in allowed web targets")
                        elif action_key in baseline_success:
                            entry = self._skip_tool(tool, "Already completed in baseline phase")
                        elif action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        else:
                            base_rate = int(nuclei_rate_limit or 0)
                            base_threads = int(gobuster_threads or 10)
                            rate_limit = args.get("rate_limit", base_rate)
                            threads = args.get("threads", base_threads)
                            rate_limit = clamp_int(rate_limit, base_rate, 0, 100)
                            threads = clamp_int(threads, base_threads, 1, 50)
                            rate_limit, threads = apply_profile(profile, rate_limit, threads)
                            proposed_wordlist = args.get("wordlist") if isinstance(args.get("wordlist"), str) else None
                            safe_wordlist = resolve_wordlist(proposed_wordlist) or resolve_wordlist(gobuster_wordlist)

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
                                if safe_wordlist:
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
                                if (
                                    not entry.get("success")
                                    and self._has_scanner("ffuf")
                                    and self._tool_enabled("ffuf", default=False)
                                ):
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
                                    ffuf_entry["reason"] = "Fallback after gobuster failure"
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
                                if "?" not in target:
                                    entry = self._skip_tool(tool, "No parameterized URL provided")
                                else:
                                    entry = self._run_tool(
                                        tool,
                                        lambda: self.scanners["sqlmap"].scan(
                                            target,
                                            cancel_event=cancel_event,
                                            timeout_seconds=self._tool_timeout_seconds("sqlmap"),
                                        ),
                                    )
                            else:
                                entry = self._skip_tool(tool, "Unsupported agentic action")
                    elif tool == "dnsenum":
                        action_target = scan_host
                        action_key = (tool, action_target or "")
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif not self._should_run_dnsenum(scan_host):
                            entry = self._skip_tool(tool, "Not a domain target")
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
                            entry = self._skip_tool(tool, "Not a domain target")
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
                        port = args.get("port")
                        if port is None:
                            port = tls_ports[0] if tls_ports else None
                        try:
                            port = int(port) if port is not None else None
                        except Exception:
                            port = None
                        action_target = scan_host
                        action_port = port
                        action_key = (tool, action_target or "", str(action_port or ""))
                        if action_key in agentic_success:
                            entry = self._skip_tool(tool, "Already completed in agentic phase")
                        elif port is None:
                            entry = self._skip_tool(tool, "No TLS ports detected (443/8443)")
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
                    if target:
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
                while actions_executed < int(max_actions):
                    if canceled():
                        break
                    remaining = int(max_actions) - actions_executed
                    try:
                        plan = plan_actions(remaining)
                    except ToolCallingNotSupported as e:
                        msg = f"Tool calling not supported; skipping agentic phase. ({e})"
                        ai_obj["planner"]["warning"] = msg
                        ai_obj["agentic_skipped"] = True
                        note("llm_error", "planner", msg, agg=agg)
                        break
                    except (ToolCallingError, Exception) as e:
                        msg = f"Tool calling failed; skipping agentic phase. ({e})"
                        ai_obj["planner"]["warning"] = msg
                        ai_obj["agentic_skipped"] = True
                        note("llm_error", "planner", msg, agg=agg)
                        break

                    plan_actions_list = plan.get("actions", [])
                    ai_obj["planner"]["plans"].append(
                        {"actions": plan_actions_list, "notes": plan.get("notes", ""), "stop": plan.get("stop", False)}
                    )
                    if plan.get("notes"):
                        ai_obj["notes"] = plan.get("notes")
                    if plan.get("stop") or not plan_actions_list:
                        break

                    def _baseline_would_skip(action: Dict[str, Any]) -> bool:
                        tool = action.get("tool")
                        spec = tool_specs.get(tool, {})
                        if spec.get("target_kind") != "web":
                            return False
                        args = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
                        target = args.get("target") if isinstance(args.get("target"), str) else None
                        if not target:
                            return True
                        if target not in allowed_web_targets and (tool != "sqlmap" or target not in sqlmap_targets):
                            return True
                        return (tool, target) in baseline_success

                    if plan_actions_list and all(_baseline_would_skip(a) for a in plan_actions_list if isinstance(a, dict)):
                        if actions_executed == 0 and not ai_obj.get("actions"):
                            ai_obj["notes"] = "Planner proposed only baseline-completed web actions; stopping agentic loop."
                        break

                    for action in plan_actions_list:
                        if actions_executed >= int(max_actions) or canceled():
                            break
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
                                "reasoning": action.get("reasoning"),
                                "phase": "agentic",
                                "success": bool(entry.get("success")) if not entry.get("skipped") else False,
                                "skipped": bool(entry.get("skipped")),
                                "error": entry.get("error") or entry.get("reason"),
                                "reason": entry.get("reason"),
                                "started_at": started_at,
                                "finished_at": finished_at,
                            }
                        )
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
                        actions_executed += 1
                        if action["tool"] == "httpx" and entry.get("success"):
                            alive = entry.get("data", {}).get("alive")
                            if isinstance(alive, list) and alive:
                                allowed_web_targets = [str(x) for x in alive if str(x).strip()]
                                web_targets = allowed_web_targets
                                agg["web_targets"] = web_targets
                        if action["tool"] == "subfinder" and entry.get("success"):
                            hosts = entry.get("data", {}).get("hosts")
                            if isinstance(hosts, list) and hosts:
                                for h in [str(x).strip() for x in hosts[:50] if str(x).strip()]:
                                    for u in (f"http://{h}", f"https://{h}"):
                                        if u not in allowed_web_targets:
                                            allowed_web_targets.append(u)
                                            web_targets.append(u)
                                agg["web_targets"] = web_targets

        # Recompute summary/findings on the combined results.
        agg["finished_at"] = time.time()
        agg["results"] = stable_sort_results(agg.get("results", []) or [])

        ffuf_fallback_hits: List[Tuple[str, int]] = []
        for entry in agg.get("results", []) or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("tool") != "ffuf" or entry.get("fallback_for") != "gobuster":
                continue
            if entry.get("phase") != "agentic":
                continue
            if not entry.get("success"):
                continue
            findings = entry.get("data", {}).get("findings")
            count = len(findings) if isinstance(findings, list) else 0
            target = str(entry.get("target") or "").strip() or "unknown-target"
            ffuf_fallback_hits.append((target, count))
        if ffuf_fallback_hits:
            total = sum(n for _, n in ffuf_fallback_hits)
            targets = ", ".join(f"{t} ({n})" for t, n in ffuf_fallback_hits[:3])
            if len(ffuf_fallback_hits) > 3:
                targets = f"{targets}, ..."
            note = (
                "ffuf fallback (after gobuster failure) ran and found "
                f"{total} paths across {len(ffuf_fallback_hits)} target(s): {targets}."
            )
            agg.setdefault("summary_notes", []).append(note)

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

        try:
            annotate_schema_validation(agg, kind="audit")
        except Exception:
            pass

        if output is not None:
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
