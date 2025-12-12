import time
from pathlib import Path
from threading import Event
from typing import Any, Dict, List, Optional

from supabash.audit import AuditOrchestrator
from supabash.agent import AgentState, MethodologyPlanner


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
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        max_actions: int = 10,
        cancel_event: Optional[Event] = None,
        progress_cb: Optional[Any] = None,
    ) -> Dict[str, Any]:
        normalized = self._normalize_target(target)
        scan_host = normalized["scan_host"]

        agg: Dict[str, Any] = {
            "target": target,
            "scan_host": scan_host,
            "results": [],
            "mode": mode,
            "started_at": time.time(),
            "react": {"max_actions": int(max_actions), "actions": [], "notes": ""},
            "tuning": {
                "nuclei_rate_limit": nuclei_rate_limit or None,
                "gobuster_threads": gobuster_threads,
                "gobuster_wordlist": gobuster_wordlist,
            },
        }
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
            return agg

        note("tool_start", "nmap", f"Running nmap ({mode})")
        nmap_entry = self._run_tool(
            "nmap",
            lambda: self.scanners["nmap"].scan(
                scan_host,
                arguments=self._nmap_args_for_mode(mode),
                cancel_event=cancel_event,
            ),
        )
        agg["results"].append(nmap_entry)
        note("tool_end", "nmap", "Finished nmap")

        if canceled() or (isinstance(nmap_entry.get("data"), dict) and nmap_entry["data"].get("canceled")):
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            return agg

        # Step 2: Build state + plan next actions
        ports: List[Dict[str, Any]] = []
        if nmap_entry.get("success"):
            for host in nmap_entry.get("data", {}).get("scan_data", {}).get("hosts", []):
                ports.extend(host.get("ports", []))
        state = AgentState(target=target, ports=ports, findings=[], actions_run=["nmap"])

        plan = self.planner.suggest(state)
        next_steps = list(plan.get("next_steps", [])) if isinstance(plan, dict) else []
        notes = plan.get("notes", "") if isinstance(plan, dict) else ""
        agg["react"]["notes"] = notes

        # Derive web targets (same as audit)
        web_targets: List[str] = []
        if normalized["base_url"]:
            web_targets = [normalized["base_url"]]
        elif nmap_entry.get("success"):
            web_targets = self._web_targets_from_nmap(scan_host, nmap_entry.get("data", {}).get("scan_data", {}))
        agg["web_targets"] = web_targets

        def run_or_skip(name: str, func, reason: str = "") -> Dict[str, Any]:
            if canceled():
                return {"tool": name, "success": False, "skipped": True, "reason": "Canceled"}
            note("tool_start", name, f"Running {name}")
            entry = self._run_tool(name, func)
            note("tool_end", name, f"Finished {name}")
            if isinstance(entry.get("data"), dict) and entry["data"].get("canceled"):
                agg["canceled"] = True
            return entry if entry.get("success") or entry.get("error") else self._skip_tool(name, reason or "Skipped")

        executed = 0
        for action in next_steps:
            if executed >= int(max_actions):
                break
            if canceled():
                agg["canceled"] = True
                break
            agg["react"]["actions"].append(action)
            executed += 1

            # Normalize actions like "hydra:ssh"
            base = str(action).split(":", 1)[0].strip().lower()

            if base == "whatweb":
                if not web_targets:
                    agg["results"].append(self._skip_tool("whatweb", "No web targets detected"))
                else:
                    agg["results"].append(run_or_skip("whatweb", lambda: self.scanners["whatweb"].scan(web_targets[0], cancel_event=cancel_event)))
                continue

            if base == "nuclei":
                if not web_targets:
                    agg["results"].append(self._skip_tool("nuclei", "No web targets detected"))
                else:
                    agg["results"].append(
                        run_or_skip(
                            "nuclei",
                            lambda: self.scanners["nuclei"].scan(web_targets[0], rate_limit=nuclei_rate_limit or None, cancel_event=cancel_event),
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
                                ),
                            )
                        )
                continue

            if base == "sqlmap":
                if normalized["sqlmap_url"]:
                    agg["results"].append(run_or_skip("sqlmap", lambda: self.scanners["sqlmap"].scan(normalized["sqlmap_url"], cancel_event=cancel_event)))
                else:
                    agg["results"].append(self._skip_tool("sqlmap", "No parameterized URL provided (include '?' in target URL)"))
                continue

            if base == "trivy":
                if not container_image:
                    agg["results"].append(self._skip_tool("trivy", "No container image provided"))
                else:
                    agg["results"].append(run_or_skip("trivy", lambda: self.scanners["trivy"].scan(container_image, cancel_event=cancel_event)))
                continue

            if base == "hydra":
                agg["results"].append(self._skip_tool("hydra", "Requires explicit usernames/passwords inputs; run manually"))
                continue

            if base == "nmap":
                agg["results"].append(self._skip_tool("nmap", "Already ran nmap in this loop"))
                continue

            agg["results"].append(self._skip_tool(base or "unknown", f"Unknown action '{action}'"))

        if canceled() or agg.get("canceled"):
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            return agg

        # Summary + remediation
        note("llm_start", "summary", "Summarizing with LLM")
        summary, llm_meta = self._summarize_with_llm(agg)
        if llm_meta:
            self._append_llm_call(agg, llm_meta)
        if summary:
            agg["summary"] = summary

        findings = self._collect_findings(agg)
        findings = self._apply_remediations(
            agg,
            findings,
            enabled=remediate,
            max_remediations=max_remediations,
            min_severity=min_remediation_severity,
        )
        agg["findings"] = findings
        agg["finished_at"] = time.time()

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

