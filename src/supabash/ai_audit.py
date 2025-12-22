from __future__ import annotations

import json
import re
import time
from pathlib import Path
from threading import Event
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from supabash.audit import AuditOrchestrator
from supabash.agent import MethodologyPlanner
from supabash import prompts
from supabash.llm_context import prepare_json_payload
from supabash.report_order import stable_sort_results
from supabash.report_schema import annotate_schema_validation


class AIAuditOrchestrator(AuditOrchestrator):
    """
    Combined "agentic audit":
      1) Run the deterministic baseline audit pipeline (no LLM)
      2) Optionally run an agentic expansion phase (heuristic or LLM-planned)
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
        nuclei_rate_limit: int = 0,
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
        llm_plan: bool = False,
        max_actions: int = 10,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        cancel_event: Optional[Event] = None,
        progress_cb: Optional[Any] = None,
        use_llm: bool = True,
    ) -> Dict[str, Any]:
        run_error: Optional[str] = None

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
            nuclei_rate_limit=nuclei_rate_limit,
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
                "planner": {"type": "llm" if llm_plan else "heuristic", "plans": [], "error": None, "warning": None},
                "max_actions": int(max_actions),
                "actions": [],
                "notes": "",
            },
        )

        # Mark baseline results for visibility.
        for entry in agg.get("results", []) or []:
            if isinstance(entry, dict):
                entry.setdefault("phase", "baseline")

        # Phase 2: Agentic expansion (best-effort; bounded)
        llm_enabled = bool(use_llm) and self._llm_enabled(default=True)
        if llm_plan and not llm_enabled:
            llm_plan = False
            ai_obj["planner"]["warning"] = "LLM disabled; falling back to heuristic planning"

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

        # Candidate actions (bounded by max_actions)
        candidates: List[str] = []
        for url in extra_web_targets:
            candidates.extend(
                [
                    f"whatweb:{url}",
                    f"nuclei:{url}",
                    f"gobuster:{url}",
                ]
            )
            if run_nikto:
                candidates.append(f"nikto:{url}")

        # Heuristic plan: take candidates in order.
        if not llm_plan and candidates:
            ai_obj["planner"]["plans"].append(
                {"next_steps": candidates[: max(1, int(max_actions))], "notes": ai_obj.get("notes", "")}
            )

        def parse_llm_plan(text: str) -> Dict[str, Any]:
            raw = (text or "").strip()
            if not raw:
                raise ValueError("empty LLM response")
            obj = None
            try:
                obj = json.loads(raw)
            except Exception:
                m = re.search(r"\{.*\}", raw, flags=re.S)
                if m:
                    obj = json.loads(m.group(0))
            if not isinstance(obj, dict):
                raise ValueError("LLM planner output is not a JSON object")
            steps = obj.get("next_steps", [])
            if steps is None:
                steps = []
            if not isinstance(steps, list):
                raise ValueError("LLM planner output next_steps is not a list")
            cleaned = []
            for s in steps:
                if s is None:
                    continue
                st = str(s).strip()
                if st:
                    cleaned.append(st)
            notes = obj.get("notes", "")
            if notes is None:
                notes = ""
            return {"next_steps": cleaned, "notes": str(notes)}

        def llm_plan_next_steps(available_actions: List[str], remaining: int) -> Dict[str, Any]:
            # Build minimal context for the planner (kept intentionally small).
            open_ports = []
            try:
                for entry in agg.get("results", []) or []:
                    if isinstance(entry, dict) and entry.get("tool") == "nmap" and entry.get("success"):
                        scan_data = entry.get("data", {}).get("scan_data", {}) if isinstance(entry.get("data"), dict) else {}
                        open_ports = self._open_ports_from_nmap(scan_data if isinstance(scan_data, dict) else {})
                        break
            except Exception:
                open_ports = []

            context_obj = {
                "target": target,
                "mode": mode,
                "remaining_actions": int(remaining),
                "available_actions": available_actions,
                "observations": {
                    "open_ports": open_ports,
                    "web_targets": web_targets,
                    "baseline_web_target": baseline_web,
                },
                "constraints": {
                    "max_actions": int(max_actions),
                    "nikto_opt_in": bool(run_nikto),
                    "hydra_opt_in": bool(run_hydra),
                    "sqlmap_requires_parameterized_url": True,
                },
            }

            max_chars = self._llm_max_chars(default=8000)
            payload, truncated = prepare_json_payload(context_obj, max_chars=max_chars)
            messages = [
                {"role": "system", "content": prompts.REACT_LLM_PLANNER_PROMPT},
                {
                    "role": "system",
                    "content": "Action format note: choose actions exactly from `available_actions` (often like `tool:https://host:port`).",
                },
                {"role": "user", "content": payload},
            ]
            if truncated:
                messages.insert(2, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

            note("llm_start", "planner", "Planning next steps with LLM", agg=agg)
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                content, meta = chat_with_meta(messages)
            else:
                content = self.llm.chat(messages)
                meta = None

            if isinstance(meta, dict):
                meta = dict(meta)
                meta.update(
                    {
                        "call_type": "plan",
                        "stage": "ai_audit",
                        "input_truncated": bool(truncated),
                        "input_chars": len(payload),
                        "max_input_chars": int(max_chars),
                    }
                )
                self._append_llm_call(agg, meta)

            plan_obj = parse_llm_plan(content)
            return plan_obj

        def run_web_action(tool: str, url: str) -> Dict[str, Any]:
            if canceled():
                return {"tool": tool, "success": False, "skipped": True, "reason": "Canceled", "phase": "agentic", "target": url}
            if not self._tool_enabled(tool, default=True):
                entry = self._skip_disabled(tool)
                entry["phase"] = "agentic"
                entry["target"] = url
                return entry
            if tool not in self.scanners:
                entry = self._skip_tool(tool, "Scanner not available")
                entry["phase"] = "agentic"
                entry["target"] = url
                return entry

            if tool == "whatweb":
                entry = self._run_tool(
                    tool,
                    lambda: self.scanners["whatweb"].scan(
                        url,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("whatweb"),
                    ),
                )
            elif tool == "nuclei":
                entry = self._run_tool(
                    tool,
                    lambda: self.scanners["nuclei"].scan(
                        url,
                        rate_limit=nuclei_rate_limit or None,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("nuclei"),
                    ),
                )
            elif tool == "gobuster":
                if gobuster_wordlist:
                    entry = self._run_tool(
                        tool,
                        lambda: self.scanners["gobuster"].scan(
                            url,
                            wordlist=gobuster_wordlist,
                            threads=gobuster_threads,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("gobuster"),
                        ),
                    )
                else:
                    entry = self._run_tool(
                        tool,
                        lambda: self.scanners["gobuster"].scan(
                            url,
                            threads=gobuster_threads,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("gobuster"),
                        ),
                    )
            elif tool == "nikto":
                try:
                    u = urlparse(url)
                    host = u.hostname or url
                    port = int(u.port or (443 if (u.scheme or "").lower() == "https" else 80))
                except Exception:
                    host = url
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
            else:
                entry = self._skip_tool(tool, "Unsupported agentic action")

            entry["phase"] = "agentic"
            entry["target"] = url
            return entry

        # Execute actions
        actions_executed = 0
        available_set = set(candidates)

        def _choose_action_from_step(step: str) -> Optional[str]:
            """
            Best-effort mapping from an LLM planner step to a concrete pending action.

            Accepts:
              - exact action strings (e.g. "nuclei:https://host:port")
              - base tool names (e.g. "nuclei" → first matching pending action)
              - space form (e.g. "nuclei https://host:port")
            """
            s = (step or "").strip()
            if not s:
                return None
            if s in available_set:
                return s

            if ":" not in s and " " in s:
                base, _, rest = s.partition(" ")
                base = base.strip().lower()
                rest = rest.strip()
                if base and rest:
                    candidate = f"{base}:{rest}"
                    if candidate in available_set:
                        return candidate

            base = s.split(":", 1)[0].strip().lower()
            if not base:
                return None

            prefix = f"{base}:"
            for a in candidates:
                if isinstance(a, str) and a in available_set and a.lower().startswith(prefix):
                    return a
            return None

        while candidates and actions_executed < int(max_actions):
            if canceled():
                break

            if llm_plan:
                remaining = int(max_actions) - actions_executed
                try:
                    plan = llm_plan_next_steps(list(candidates), remaining=remaining)
                except Exception as e:
                    llm_plan_failed = f"LLM planning failed: {e}"
                    ai_obj["planner"]["error"] = llm_plan_failed
                    agg["error"] = llm_plan_failed
                    agg["failed"] = True
                    run_error = llm_plan_failed
                    break

                # Filter steps to the provided available set and handle stop.
                steps = []
                stop_requested = False
                for step in plan.get("next_steps", []):
                    base = str(step).split(":", 1)[0].strip().lower()
                    if base in ("stop", "done", "finish"):
                        stop_requested = True
                        break
                    chosen = _choose_action_from_step(str(step))
                    if chosen and chosen not in steps:
                        steps.append(chosen)

                ai_obj["planner"]["plans"].append({"next_steps": steps, "notes": plan.get("notes", "")})
                if stop_requested or not steps:
                    break
                queue = steps
            else:
                remaining = int(max_actions) - actions_executed
                queue = list(candidates[:remaining])

            for action in list(queue):
                if actions_executed >= int(max_actions) or canceled():
                    break
                if action not in available_set:
                    continue
                candidates.remove(action)
                available_set.remove(action)

                tool, url = action.split(":", 1)
                tool = tool.strip().lower()
                url = url.strip()

                note("tool_start", tool, f"Running {tool} (agentic)", agg=agg)
                started_at = time.time()
                entry = run_web_action(tool, url)
                finished_at = time.time()
                note("tool_end", tool, f"Finished {tool} (agentic)", agg=agg)

                agg.setdefault("results", []).append(entry)
                ai_obj["actions"].append(
                    {
                        "action": action,
                        "tool": tool,
                        "target": url,
                        "phase": "agentic",
                        "success": bool(entry.get("success")) if not entry.get("skipped") else False,
                        "skipped": bool(entry.get("skipped")),
                        "error": entry.get("error") or entry.get("reason"),
                        "started_at": started_at,
                        "finished_at": finished_at,
                    }
                )
                actions_executed += 1

        # If LLM planning was required and failed, stop and write a best-effort report
        # (baseline phase + any already-run agentic actions).
        if agg.get("failed") and run_error:
            agg["finished_at"] = time.time()
            agg["results"] = stable_sort_results(agg.get("results", []) or [])
            agg["run_error"] = run_error
            try:
                annotate_schema_validation(agg, kind="audit")
            except Exception:
                pass
            if output is not None:
                try:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(json.dumps(agg, indent=2), encoding="utf-8")
                    agg["saved_to"] = str(output)
                except Exception as e:
                    agg["saved_to"] = None
                    agg["write_error"] = str(e)
            else:
                agg["saved_to"] = None
            return agg

        # Recompute summary/findings on the combined results.
        agg["finished_at"] = time.time()
        agg["results"] = stable_sort_results(agg.get("results", []) or [])

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
            if summary:
                agg["summary"] = summary

        findings = self._apply_remediations(
            agg,
            findings,
            enabled=remediate and llm_enabled,
            max_remediations=max_remediations,
            min_severity=min_remediation_severity,
        )
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
