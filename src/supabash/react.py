import json
import re
import time
from pathlib import Path
from threading import Event
from typing import Any, Dict, List, Optional

from supabash.audit import AuditOrchestrator
from supabash.agent import AgentState, MethodologyPlanner
from supabash import prompts
from supabash.llm_context import prepare_json_payload
from supabash.report_schema import SCHEMA_VERSION, annotate_schema_validation
from supabash.aggressive_caps import apply_aggressive_caps


class ReActOrchestrator(AuditOrchestrator):
    """
    A simple ReAct-style loop:
      - Run nmap
      - Plan next actions from open ports/inputs
      - Execute suggested tools (with guards/skips)
      - Summarize + (optional) remediate findings
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
        llm_plan: bool = False,
        run_hydra: bool = False,
        hydra_usernames: Optional[str] = None,
        hydra_passwords: Optional[str] = None,
        hydra_services: Optional[str] = None,
        hydra_threads: int = 4,
        hydra_options: Optional[str] = None,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        max_actions: int = 10,
        cancel_event: Optional[Event] = None,
        progress_cb: Optional[Any] = None,
        use_llm: bool = True,
    ) -> Dict[str, Any]:
        normalized = self._normalize_target(target)
        scan_host = normalized["scan_host"]

        cfg_obj = None
        try:
            cfg_obj = getattr(self.llm, "config", None)
            cfg_obj = getattr(cfg_obj, "config", None) if cfg_obj is not None else None
        except Exception:
            cfg_obj = None
        cfg_dict = cfg_obj if isinstance(cfg_obj, dict) else {}

        nuclei_rate_limit, gobuster_threads, _, caps_meta = apply_aggressive_caps(
            mode,
            config=cfg_dict,
            nuclei_rate_limit=nuclei_rate_limit,
            gobuster_threads=gobuster_threads,
            max_workers=None,
        )

        llm_enabled = bool(use_llm) and self._llm_enabled(default=True)
        if llm_plan and not llm_enabled:
            # Graceful degradation: fall back to heuristic planning when LLM is disabled.
            llm_plan = False

        agg: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "scan_host": scan_host,
            "results": [],
            "mode": mode,
            "started_at": time.time(),
            "react": {
                "max_actions": int(max_actions),
                "actions": [],
                "notes": "",
                "planner": {"type": "llm" if llm_plan else "heuristic", "plans": [], "error": None},
            },
            "tuning": {
                "nuclei_rate_limit": nuclei_rate_limit or None,
                "gobuster_threads": gobuster_threads,
                "gobuster_wordlist": gobuster_wordlist,
                "hydra_enabled": bool(run_hydra),
                "hydra_services": hydra_services,
                "hydra_threads": int(hydra_threads),
            },
            "safety": {"aggressive_caps": caps_meta},
        }
        if not llm_enabled:
            agg["llm"] = {"enabled": False, "reason": "Disabled by config or --no-llm", "calls": []}
        if use_llm and not llm_enabled:
            # When config disables LLM but the caller asked for it, record for visibility.
            agg["react"]["planner"]["warning"] = "LLM disabled; falling back to heuristic planner"
        if container_image:
            agg["container_image"] = container_image

        def canceled() -> bool:
            return bool(cancel_event and cancel_event.is_set())

        def note(event: str, tool: str = "", message: str = "") -> None:
            if callable(progress_cb):
                try:
                    progress_cb(event=event, tool=tool, message=message, agg=agg)
                except Exception:
                    pass

        # Step 1: Recon (nmap)
        if canceled():
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            try:
                annotate_schema_validation(agg, kind="react")
            except Exception:
                pass
            return agg

        note("tool_start", "nmap", f"Running nmap ({mode})")
        nmap_entry = self._run_tool_if_enabled(
            "nmap",
            lambda: self.scanners["nmap"].scan(
                scan_host,
                arguments=self._nmap_args_for_mode(mode),
                cancel_event=cancel_event,
                timeout_seconds=self._tool_timeout_seconds("nmap"),
            ),
        )
        agg["results"].append(nmap_entry)
        note("tool_end", "nmap", "Finished nmap")

        if canceled() or (isinstance(nmap_entry.get("data"), dict) and nmap_entry["data"].get("canceled")):
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            try:
                annotate_schema_validation(agg, kind="react")
            except Exception:
                pass
            return agg

        # Step 2: Build state + plan next actions
        ports: List[Dict[str, Any]] = []
        if nmap_entry.get("success"):
            for host in nmap_entry.get("data", {}).get("scan_data", {}).get("hosts", []):
                ports.extend(host.get("ports", []))
        state = AgentState(target=target, ports=ports, findings=[], actions_run=["nmap"])

        actions_queue: List[str] = []
        stop_requested = False
        llm_plan_failed = False

        if not llm_plan:
            plan = self.planner.suggest(state)
            next_steps = list(plan.get("next_steps", [])) if isinstance(plan, dict) else []
            notes = plan.get("notes", "") if isinstance(plan, dict) else ""
            agg["react"]["notes"] = notes
            actions_queue = list(next_steps)
            try:
                preview = ", ".join(str(s) for s in next_steps[:10])
                if len(next_steps) > 10:
                    preview = f"{preview}, …"
                msg = f"Planned next steps: {preview}" if preview else "Planner returned no next steps."
                note("plan_ready", "planner", msg)
                if notes:
                    note("methodology", "planner", notes)
            except Exception:
                pass

        # Derive web targets (same as audit)
        web_targets: List[str] = []
        if normalized["base_url"]:
            web_targets = [normalized["base_url"]]
        elif nmap_entry.get("success"):
            web_targets = self._web_targets_from_nmap(scan_host, nmap_entry.get("data", {}).get("scan_data", {}))

        # Optional domain expansion: subfinder can add candidates beyond nmap-derived ports.
        if self._should_run_dnsenum(scan_host) and self._has_scanner("subfinder") and self._tool_enabled("subfinder", default=False):
            try:
                note("tool_start", "subfinder", "Running subfinder")
            except Exception:
                pass
            sub_entry = self._run_tool(
                "subfinder",
                lambda: self.scanners["subfinder"].scan(
                    scan_host,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("subfinder"),
                ),
            )
            agg["results"].append(sub_entry)
            try:
                note("tool_end", "subfinder", "Finished subfinder")
            except Exception:
                pass
            if sub_entry.get("success"):
                hosts = sub_entry.get("data", {}).get("hosts")
                if isinstance(hosts, list) and hosts:
                    for h in [str(x).strip() for x in hosts[:50] if str(x).strip()]:
                        for u in (f"http://{h}", f"https://{h}"):
                            if u not in web_targets:
                                web_targets.append(u)
        # Best-effort probe to validate endpoints before running web tools.
        if web_targets and self._has_scanner("httpx"):
            try:
                note("tool_start", "httpx", "Probing web targets with httpx")
            except Exception:
                pass
            httpx_entry = self._run_tool_if_enabled(
                "httpx",
                lambda: self.scanners["httpx"].scan(
                    web_targets,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("httpx"),
                ),
            )
            agg["results"].append(httpx_entry)
            try:
                note("tool_end", "httpx", "Finished httpx")
            except Exception:
                pass
            if httpx_entry.get("success"):
                alive = httpx_entry.get("data", {}).get("alive")
                if isinstance(alive, list) and alive:
                    web_targets = [str(x) for x in alive if str(x).strip()]
        agg["web_targets"] = web_targets

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

        def llm_plan_next_steps(remaining: int) -> Dict[str, Any]:
            allowed_bases = [
                "subfinder",
                "httpx",
                "whatweb",
                "nuclei",
                "gobuster",
                "ffuf",
                "katana",
                "dnsenum",
                "sslscan",
                "enum4linux-ng",
                "nikto",
                "searchsploit",
                "sqlmap",
                "trivy",
                "stop",
            ]

            open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {})) if nmap_entry.get("success") else []
            tls_ports = [p for p in open_ports if p in (443, 8443)]
            smb_detected = any(p in (139, 445) for p in open_ports)

            results_summary = []
            for r in agg.get("results", []):
                if not isinstance(r, dict):
                    continue
                results_summary.append(
                    {
                        "tool": r.get("tool"),
                        "success": r.get("success"),
                        "skipped": r.get("skipped"),
                        "reason": r.get("reason"),
                        "error": r.get("error"),
                    }
                )

            enabled_map = {b: bool(self._tool_enabled(b, default=True)) for b in allowed_bases if b != "stop"}
            available_map = {b: bool(b in self.scanners) for b in allowed_bases if b != "stop"}

            findings_preview = []
            try:
                findings_preview = self._collect_findings(agg)[-20:]
            except Exception:
                findings_preview = []

            context_obj = {
                "target": target,
                "mode": mode,
                "scan_host": scan_host,
                "open_ports": open_ports,
                "web_targets": web_targets,
                "observations": {
                    "results": results_summary[-12:],
                    "findings": findings_preview,
                },
                "executed_actions": list(agg.get("react", {}).get("actions", []))[-20:],
                "remaining_actions": int(remaining),
                "available_actions": allowed_bases,
                "tool_enabled": enabled_map,
                "tool_available": available_map,
                "preconditions": {
                    "sqlmap_url_provided": bool(normalized.get("sqlmap_url")),
                    "container_image_provided": bool(container_image),
                    "domain_target": bool(self._should_run_dnsenum(scan_host)),
                    "tls_ports_detected": tls_ports,
                    "smb_ports_detected": bool(smb_detected),
                },
            }

            max_chars = self._llm_max_chars(default=8000)
            payload, truncated = prepare_json_payload(context_obj, max_chars=max_chars)
            messages = [
                {"role": "system", "content": prompts.REACT_LLM_PLANNER_PROMPT},
                {"role": "user", "content": payload},
            ]
            if truncated:
                messages.insert(1, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

            note("llm_start", "planner", "Planning next steps with LLM")
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
                        "input_truncated": bool(truncated),
                        "input_chars": len(payload),
                        "max_input_chars": int(max_chars),
                    }
                )
                self._append_llm_call(agg, meta)

            plan_obj = parse_llm_plan(content)

            # Filter to allowed + stop sentinel
            filtered: List[str] = []
            local_stop = False
            for step in plan_obj.get("next_steps", []):
                base = str(step).split(":", 1)[0].strip().lower()
                if base in ("stop", "done", "finish"):
                    local_stop = True
                    break
                if base not in allowed_bases:
                    continue
                filtered.append(step)

            plan_obj["next_steps"] = filtered
            plan_obj["_stop"] = bool(local_stop)
            return plan_obj

        def run_or_skip(name: str, func, reason: str = "") -> Dict[str, Any]:
            if canceled():
                try:
                    note("tool_skip", name, "Canceled")
                except Exception:
                    pass
                return {"tool": name, "success": False, "skipped": True, "reason": "Canceled"}
            if not self._tool_enabled(name, default=True):
                try:
                    note("tool_skip", name, "Disabled by config (tools.<name>.enabled=false)")
                except Exception:
                    pass
                return self._skip_disabled(name)
            if name not in self.scanners:
                try:
                    note("tool_skip", name, "Scanner not available")
                except Exception:
                    pass
                return self._skip_tool(name, "Scanner not available")
            note("tool_start", name, f"Running {name}")
            entry = self._run_tool(name, func)
            note("tool_end", name, f"Finished {name}")
            if isinstance(entry.get("data"), dict) and entry["data"].get("canceled"):
                agg["canceled"] = True
            return entry if entry.get("success") or entry.get("error") else self._skip_tool(name, reason or "Skipped")

        executed = 0
        while executed < int(max_actions):
            if canceled():
                agg["canceled"] = True
                break
            if llm_plan and not actions_queue and not stop_requested and not llm_plan_failed:
                remaining = int(max_actions) - executed
                try:
                    plan_obj = llm_plan_next_steps(remaining)
                    agg["react"]["planner"]["plans"].append(plan_obj)
                    notes = plan_obj.get("notes", "")
                    if isinstance(notes, str) and notes.strip():
                        agg["react"]["notes"] = notes.strip()
                        note("methodology", "llm_planner", notes.strip())
                    steps = list(plan_obj.get("next_steps", []))
                    preview = ", ".join(str(s) for s in steps[:10])
                    msg = f"Planned next steps: {preview}" if preview else "LLM planner returned no next steps."
                    note("plan_ready", "llm_planner", msg)
                    actions_queue = list(steps)
                    stop_requested = bool(plan_obj.get("_stop")) or not actions_queue
                except Exception as e:
                    llm_plan_failed = True
                    err = f"LLM planning failed: {e}"
                    agg["error"] = err
                    agg["failed"] = True
                    agg["react"]["planner"]["error"] = err
                    note("error", "llm_planner", err)
                    break

            if not actions_queue:
                break

            action = actions_queue.pop(0)
            agg["react"]["actions"].append(action)
            executed += 1
            try:
                note("action_selected", "react", f"{executed}/{int(max_actions)}: {action}")
            except Exception:
                pass

            # Normalize actions like "hydra:ssh"
            action_str = str(action)
            base, _, suffix = action_str.partition(":")
            base = base.strip().lower()
            suffix = suffix.strip().lower()

            if base == "httpx":
                if not web_targets:
                    agg["results"].append(self._skip_tool("httpx", "No web targets detected"))
                else:
                    entry = run_or_skip(
                        "httpx",
                        lambda: self.scanners["httpx"].scan(
                            web_targets,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("httpx"),
                        ),
                    )
                    agg["results"].append(entry)
                    if entry.get("success"):
                        alive = entry.get("data", {}).get("alive")
                        if isinstance(alive, list) and alive:
                            web_targets = [str(x) for x in alive if str(x).strip()]
                            agg["web_targets"] = web_targets
                continue

            if base == "whatweb":
                if not web_targets:
                    agg["results"].append(self._skip_tool("whatweb", "No web targets detected"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "whatweb",
                            lambda: self.scanners["whatweb"].scan(
                                web_targets[0],
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("whatweb"),
                            ),
                        )
                    )
                continue

            if base == "nuclei":
                if not web_targets:
                    agg["results"].append(self._skip_tool("nuclei", "No web targets detected"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "nuclei",
                            lambda: self.scanners["nuclei"].scan(
                                web_targets[0],
                                rate_limit=nuclei_rate_limit or None,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("nuclei"),
                            ),
                        )
                    )
                continue

            if base == "gobuster":
                if not web_targets:
                    agg["results"].append(self._skip_tool("gobuster", "No web targets detected"))
                else:
                    if gobuster_wordlist:
                        agg["results"].append(
                            run_or_skip(
                                "gobuster",
                                lambda: self.scanners["gobuster"].scan(
                                    web_targets[0],
                                    wordlist=gobuster_wordlist,
                                    threads=gobuster_threads,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("gobuster"),
                                ),
                            )
                        )
                    else:
                        agg["results"].append(
                            run_or_skip(
                                "gobuster",
                                lambda: self.scanners["gobuster"].scan(
                                    web_targets[0],
                                    threads=gobuster_threads,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("gobuster"),
                                ),
                            )
                        )
                continue

            if base == "ffuf":
                if not web_targets:
                    agg["results"].append(self._skip_tool("ffuf", "No web targets detected"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "ffuf",
                            lambda: self.scanners["ffuf"].scan(
                                web_targets[0],
                                wordlist=gobuster_wordlist,
                                threads=max(10, int(gobuster_threads)),
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("ffuf"),
                            ),
                        )
                    )
                continue

            if base == "katana":
                if not web_targets:
                    agg["results"].append(self._skip_tool("katana", "No web targets detected"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "katana",
                            lambda: self.scanners["katana"].crawl(
                                web_targets[0],
                                depth=int(self._tool_config("katana").get("depth", 3) or 3),
                                concurrency=int(self._tool_config("katana").get("concurrency", 10) or 10),
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("katana"),
                            ),
                        )
                    )
                continue

            if base == "sqlmap":
                if normalized["sqlmap_url"]:
                    agg["results"].append(
                        run_or_skip(
                            "sqlmap",
                            lambda: self.scanners["sqlmap"].scan(
                                normalized["sqlmap_url"],
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("sqlmap"),
                            ),
                        )
                    )
                else:
                    agg["results"].append(self._skip_tool("sqlmap", "No parameterized URL provided (include '?' in target URL)"))
                continue

            if base == "subfinder":
                if not self._should_run_dnsenum(scan_host):
                    agg["results"].append(self._skip_tool("subfinder", "Not a domain target"))
                    continue
                agg["results"].append(
                    run_or_skip(
                        "subfinder",
                        lambda: self.scanners["subfinder"].scan(
                            scan_host,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("subfinder"),
                        ),
                    )
                )
                last = agg["results"][-1]
                if last.get("success"):
                    hosts = last.get("data", {}).get("hosts")
                    if isinstance(hosts, list) and hosts:
                        for h in [str(x).strip() for x in hosts[:50] if str(x).strip()]:
                            for u in (f"http://{h}", f"https://{h}"):
                                if u not in web_targets:
                                    web_targets.append(u)
                        agg["web_targets"] = web_targets
                continue

            if base == "trivy":
                if not container_image:
                    agg["results"].append(self._skip_tool("trivy", "No container image provided"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "trivy",
                            lambda: self.scanners["trivy"].scan(
                                container_image,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("trivy"),
                            ),
                        )
                    )
                continue

            if base == "hydra":
                if not run_hydra:
                    agg["results"].append(
                        self._skip_tool(
                            "hydra",
                            "Opt-in only; re-run with --hydra --hydra-usernames PATH --hydra-passwords PATH",
                        )
                    )
                    continue
                if not hydra_usernames or not hydra_passwords:
                    agg["results"].append(self._skip_tool("hydra", "Missing --hydra-usernames/--hydra-passwords"))
                    continue
                if not self._has_scanner("hydra"):
                    agg["results"].append(self._skip_tool("hydra", "Scanner not available"))
                    continue

                svc = suffix or "ssh"
                allowed = hydra_services or "ssh,ftp"
                allowed_list = [s.strip().lower() for s in str(allowed).replace(";", ",").split(",") if s.strip()]
                if allowed_list and svc not in allowed_list:
                    agg["results"].append(self._skip_tool("hydra", f"Service '{svc}' not enabled (allowed: {', '.join(allowed_list)})"))
                    continue

                svc_ports: List[int] = []
                if nmap_entry.get("success"):
                    for host in nmap_entry.get("data", {}).get("scan_data", {}).get("hosts", []):
                        for p in host.get("ports", []) or []:
                            try:
                                if str(p.get("state", "")).lower() != "open":
                                    continue
                                if str(p.get("service", "")).strip().lower() != svc:
                                    continue
                                svc_ports.append(int(p.get("port")))
                            except Exception:
                                continue
                svc_ports = sorted(set(svc_ports))
                if not svc_ports:
                    agg["results"].append(self._skip_tool("hydra", f"No {svc} service detected by nmap"))
                    continue

                port = svc_ports[0]
                extra = hydra_options or ""
                opt = f"-s {port} -t {int(hydra_threads)} {extra}".strip()
                agg["results"].append(
                    run_or_skip(
                        "hydra",
                        lambda: self.scanners["hydra"].run(
                            scan_host,
                            svc,
                            hydra_usernames,
                            hydra_passwords,
                            options=opt,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("hydra"),
                        ),
                    )
                )
                continue

            if base == "dnsenum":
                if self._should_run_dnsenum(scan_host):
                    agg["results"].append(
                        run_or_skip(
                            "dnsenum",
                            lambda: self.scanners["dnsenum"].scan(
                                scan_host,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("dnsenum"),
                            ),
                        )
                    )
                else:
                    agg["results"].append(self._skip_tool("dnsenum", "Not a domain target"))
                continue

            if base == "sslscan":
                open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {})) if nmap_entry.get("success") else []
                tls_ports = [p for p in open_ports if p in (443, 8443)]
                if not tls_ports:
                    agg["results"].append(self._skip_tool("sslscan", "No TLS ports detected (443/8443)"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "sslscan",
                            lambda: self.scanners["sslscan"].scan(
                                scan_host,
                                port=tls_ports[0],
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("sslscan"),
                            ),
                        )
                    )
                continue

            if base == "enum4linux-ng":
                open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {})) if nmap_entry.get("success") else []
                if any(p in (139, 445) for p in open_ports):
                    agg["results"].append(
                        run_or_skip(
                            "enum4linux-ng",
                            lambda: self.scanners["enum4linux-ng"].scan(
                                scan_host,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("enum4linux-ng"),
                            ),
                        )
                    )
                else:
                    agg["results"].append(self._skip_tool("enum4linux-ng", "No SMB ports detected (139/445)"))
                continue

            if base == "searchsploit":
                if not self._has_scanner("searchsploit"):
                    agg["results"].append(self._skip_tool("searchsploit", "Scanner not available"))
                    continue
                if not nmap_entry.get("success"):
                    agg["results"].append(self._skip_tool("searchsploit", "No nmap results to derive service fingerprints"))
                    continue

                scan_data = nmap_entry.get("data", {}).get("scan_data", {}) if isinstance(nmap_entry.get("data"), dict) else {}
                queries: List[str] = []
                for host in (scan_data or {}).get("hosts", []) or []:
                    for p in host.get("ports", []) or []:
                        try:
                            if str(p.get("state", "")).lower() != "open":
                                continue
                            svc = str(p.get("service") or "").strip()
                            prod = str(p.get("product") or "").strip()
                            ver = str(p.get("version") or "").strip()
                            if not (svc or prod):
                                continue
                            q = " ".join(x for x in (prod, ver, svc) if x).strip()
                            if q and q not in queries:
                                queries.append(q)
                        except Exception:
                            continue

                if not queries:
                    agg["results"].append(self._skip_tool("searchsploit", "No version/service fingerprints available"))
                    continue

                # Run a few bounded lookups (one result entry per query).
                for q in queries[:3]:
                    agg["results"].append(
                        run_or_skip(
                            "searchsploit",
                            lambda q=q: self.scanners["searchsploit"].search(
                                q,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("searchsploit"),
                            ),
                        )
                    )
                continue

            if base == "nikto":
                if not web_targets:
                    agg["results"].append(self._skip_tool("nikto", "No web targets detected"))
                else:
                    from urllib.parse import urlparse

                    try:
                        u = urlparse(web_targets[0])
                        host = u.hostname or scan_host
                        port = int(u.port or (443 if (u.scheme or "").lower() == "https" else 80))
                    except Exception:
                        host = scan_host
                        port = 80
                    agg["results"].append(
                        run_or_skip(
                            "nikto",
                            lambda: self.scanners["nikto"].scan(
                                host,
                                port=port,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("nikto"),
                            ),
                        )
                    )
                continue

            if base == "nmap":
                agg["results"].append(self._skip_tool("nmap", "Already ran nmap in this loop"))
                continue

            agg["results"].append(self._skip_tool(base or "unknown", f"Unknown action '{action}'"))

        if canceled() or agg.get("canceled"):
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            try:
                annotate_schema_validation(agg, kind="react")
            except Exception:
                pass
            return agg

        if agg.get("failed"):
            agg["finished_at"] = time.time()
            try:
                annotate_schema_validation(agg, kind="react")
            except Exception:
                pass
            note("done", "react", "ReAct loop finished (failed)")
            if output is not None:
                try:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(json_dump(agg), encoding="utf-8")
                    agg["saved_to"] = str(output)
                except Exception as e:
                    agg["saved_to"] = None
                    agg["write_error"] = str(e)
            else:
                agg["saved_to"] = None
            return agg

        findings = self._collect_findings(agg)
        # Summary + remediation
        if llm_enabled:
            note("llm_start", "summary", "Summarizing with LLM")
            ctx = self._build_llm_summary_context(agg, findings)
            summary, llm_meta = self._summarize_with_llm(agg, context=ctx)
            if llm_meta:
                self._append_llm_call(agg, llm_meta)
            if summary:
                agg["summary"] = summary
        else:
            if remediate:
                agg.setdefault("llm", {})["remediation_skipped"] = True

        findings = self._apply_remediations(
            agg,
            findings,
            enabled=remediate and llm_enabled,
            max_remediations=max_remediations,
            min_severity=min_remediation_severity,
        )
        agg["findings"] = findings
        agg["finished_at"] = time.time()
        try:
            annotate_schema_validation(agg, kind="react")
        except Exception:
            pass
        note("done", "react", "ReAct loop finished")

        if output is not None:
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json_dump(agg), encoding="utf-8")
                agg["saved_to"] = str(output)
            except Exception as e:
                agg["saved_to"] = None
                agg["write_error"] = str(e)
        else:
            agg["saved_to"] = None

        return agg


def json_dump(obj: Any) -> str:
    import json

    return json.dumps(obj, indent=2)
