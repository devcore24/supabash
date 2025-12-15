import json
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import time
from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    WhatWebScanner,
    NucleiScanner,
    GobusterScanner,
    SqlmapScanner,
    HydraRunner,
    NiktoScanner,
    SslscanScanner,
    DnsenumScanner,
    Enum4linuxNgScanner,
    TrivyScanner,
    SupabaseRLSChecker,
)
from supabash.llm import LLMClient
from supabash import prompts
from supabash.llm_context import prepare_json_payload
from supabash.report_order import stable_sort_results
from supabash.report_schema import SCHEMA_VERSION, annotate_schema_validation
from supabash.aggressive_caps import apply_aggressive_caps

logger = setup_logger(__name__)


class AuditOrchestrator:
    """
    Simple orchestrator to run available scanners and aggregate results.
    """

    def __init__(
        self,
        scanners: Optional[Dict[str, Any]] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        # Allow dependency injection for testing
        self.scanners = scanners or {
            "nmap": NmapScanner(),
            "whatweb": WhatWebScanner(),
            "nuclei": NucleiScanner(),
            "gobuster": GobusterScanner(),
            "sqlmap": SqlmapScanner(),
            "hydra": HydraRunner(),
            "nikto": NiktoScanner(),
            "sslscan": SslscanScanner(),
            "dnsenum": DnsenumScanner(),
            "enum4linux-ng": Enum4linuxNgScanner(),
            "trivy": TrivyScanner(),
            "supabase_rls": SupabaseRLSChecker(),
        }
        self.llm = llm_client or LLMClient()

    def _has_scanner(self, name: str) -> bool:
        return isinstance(self.scanners, dict) and name in self.scanners and self.scanners.get(name) is not None

    def _open_ports_from_nmap(self, nmap_data: Dict[str, Any]) -> List[int]:
        ports: List[int] = []
        for host in (nmap_data or {}).get("hosts", []) or []:
            for p in host.get("ports", []) or []:
                try:
                    if str(p.get("state", "")).lower() != "open":
                        continue
                    ports.append(int(p.get("port")))
                except Exception:
                    continue
        return sorted(set(ports))

    def _is_ip_literal(self, host: str) -> bool:
        try:
            ipaddress.ip_address((host or "").strip())
            return True
        except Exception:
            return False

    def _should_run_dnsenum(self, scan_host: str) -> bool:
        host = (scan_host or "").strip()
        if not host or "/" in host or ":" in host:
            return False
        return not self._is_ip_literal(host)

    def _tool_config(self, tool: str) -> Dict[str, Any]:
        """
        Returns tool config dict (best-effort).
        Supports both '-' and '_' variants in config keys.
        """
        tool = str(tool or "").strip()
        if not tool:
            return {}
        keys = [tool]
        if "-" in tool:
            keys.append(tool.replace("-", "_"))
        if "_" in tool:
            keys.append(tool.replace("_", "-"))

        cfg_obj = None
        try:
            cfg_obj = getattr(self.llm, "config", None)
            cfg_obj = getattr(cfg_obj, "config", None) if cfg_obj is not None else None
        except Exception:
            cfg_obj = None
        if not isinstance(cfg_obj, dict):
            return {}

        tools_cfg = cfg_obj.get("tools", {})
        if not isinstance(tools_cfg, dict):
            return {}
        for k in keys:
            v = tools_cfg.get(k)
            if isinstance(v, dict):
                return v
        return {}

    def _tool_timeout_seconds(self, tool: str) -> Optional[int]:
        cfg = self._tool_config(tool)
        if not cfg:
            return None
        value = cfg.get("timeout_seconds", cfg.get("timeout"))
        if value is None:
            return None
        try:
            return int(value)
        except Exception:
            return None

    def _tool_enabled(self, tool: str, default: bool = True) -> bool:
        cfg = self._tool_config(tool)
        if not cfg:
            return bool(default)
        enabled = cfg.get("enabled")
        if enabled is None:
            return bool(default)
        return bool(enabled)

    def _skip_disabled(self, tool: str) -> Dict[str, Any]:
        return self._skip_tool(tool, "Disabled by config (tools.<name>.enabled=false)")

    def _run_tool_if_enabled(self, name: str, func) -> Dict[str, Any]:
        if not self._tool_enabled(name, default=True):
            return self._skip_disabled(name)
        return self._run_tool(name, func)

    def _run_tool(self, name: str, func) -> Dict[str, Any]:
        try:
            result = func()
            success = result.get("success", False)
            entry: Dict[str, Any] = {"tool": name, "success": success, "data": result}
            # Auditability: bubble up the executed command (if the tool wrapper provides it).
            if isinstance(result, dict):
                cmd = result.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    entry["command"] = cmd.strip()
            if not success and isinstance(result, dict):
                err = result.get("error")
                if isinstance(err, str) and err.strip():
                    entry["error"] = err.strip()
            return entry
        except Exception as e:
            logger.error(f"{name} execution failed: {e}")
            return {"tool": name, "success": False, "error": str(e)}

    def _skip_tool(self, name: str, reason: str) -> Dict[str, Any]:
        return {"tool": name, "success": False, "skipped": True, "reason": reason}

    def _llm_max_chars(self, default: int = 12000) -> int:
        try:
            cfg = getattr(self.llm, "config", None)
            if cfg is not None and hasattr(cfg, "config"):
                return int(cfg.config.get("llm", {}).get("max_input_chars", default))
        except Exception:
            return default
        return default

    def _llm_enabled(self, default: bool = True) -> bool:
        try:
            cfg = getattr(self.llm, "config", None)
            cfg_dict = getattr(cfg, "config", None) if cfg is not None else None
            if isinstance(cfg_dict, dict):
                llm_cfg = cfg_dict.get("llm", {})
                if isinstance(llm_cfg, dict):
                    enabled = llm_cfg.get("enabled")
                    if enabled is None:
                        return bool(default)
                    return bool(enabled)
        except Exception:
            return bool(default)
        return bool(default)

    def _append_llm_call(self, agg: Dict[str, Any], meta: Optional[Dict[str, Any]]) -> None:
        if not isinstance(meta, dict):
            return
        llm_obj = agg.setdefault("llm", {})
        calls = llm_obj.setdefault("calls", [])
        if isinstance(calls, list):
            calls.append(meta)

    def _summarize_with_llm(self, agg: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        try:
            max_chars = self._llm_max_chars()
            payload, truncated = prepare_json_payload(agg, max_chars=max_chars)
            messages = [
                {"role": "system", "content": prompts.ANALYZER_PROMPT},
                {"role": "user", "content": payload},
            ]
            if truncated:
                messages.insert(1, {"role": "system", "content": "Note: Tool output was truncated to fit context limits."})
            meta = None
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                result = chat_with_meta(messages)
                if isinstance(result, tuple) and len(result) == 2:
                    content, meta = result
                else:
                    content = self.llm.chat(messages)
            else:
                content = self.llm.chat(messages)
            if meta is not None:
                meta = dict(meta)
                meta.update(
                    {
                        "call_type": "summary",
                        "input_truncated": bool(truncated),
                        "input_chars": len(payload),
                        "max_input_chars": int(max_chars),
                    }
                )
            return json.loads(content), meta
        except Exception as e:
            logger.error(f"LLM summary failed: {e}")
            return None, None

    def _severity_rank(self, severity: str) -> int:
        sev = (severity or "").upper()
        ranks = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return ranks.get(sev, 1)

    def _remediate_finding(self, finding: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        try:
            max_chars = self._llm_max_chars()
            payload, truncated = prepare_json_payload(
                {
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", ""),
                    "evidence": finding.get("evidence", ""),
                    "context": {"tool": finding.get("tool"), "type": finding.get("type")},
                },
                max_chars=max_chars,
            )
            messages = [
                {"role": "system", "content": prompts.REMEDIATOR_PROMPT},
                {"role": "user", "content": payload},
            ]
            if truncated:
                messages.insert(1, {"role": "system", "content": "Note: Input was truncated to fit context limits."})

            meta = None
            chat_with_meta = getattr(self.llm, "chat_with_meta", None)
            if callable(chat_with_meta):
                result = chat_with_meta(messages)
                if isinstance(result, tuple) and len(result) == 2:
                    content, meta = result
                else:
                    content = self.llm.chat(messages)
            else:
                content = self.llm.chat(messages)

            parsed = json.loads(content)
            if isinstance(meta, dict):
                meta = dict(meta)
                meta.update(
                    {
                        "call_type": "remediation",
                        "finding_title": finding.get("title", ""),
                        "input_truncated": bool(truncated),
                        "input_chars": len(payload),
                        "max_input_chars": int(max_chars),
                    }
                )
            return parsed if isinstance(parsed, dict) else {"raw": parsed}, meta
        except Exception as e:
            logger.error(f"LLM remediation failed: {e}")
            return None, None

    def _apply_remediations(
        self,
        agg: Dict[str, Any],
        findings: List[Dict[str, Any]],
        *,
        enabled: bool,
        max_remediations: int,
        min_severity: str,
    ) -> List[Dict[str, Any]]:
        if not enabled:
            return findings

        threshold = self._severity_rank(min_severity)
        candidates = []
        for idx, f in enumerate(findings):
            rank = self._severity_rank(f.get("severity", "INFO"))
            if rank < threshold:
                continue
            candidates.append((rank, 0 if not f.get("recommendation") else 1, idx))

        candidates.sort(reverse=True)
        for _, __, idx in candidates[: max(0, int(max_remediations))]:
            f = findings[idx]
            remediation, meta = self._remediate_finding(f)
            if remediation:
                f["remediation"] = remediation
                if not f.get("recommendation") and isinstance(remediation, dict):
                    summary = remediation.get("summary")
                    if isinstance(summary, str) and summary.strip():
                        f["recommendation"] = summary.strip()
                if isinstance(remediation, dict):
                    code_sample = remediation.get("code_sample")
                    if isinstance(code_sample, str) and code_sample.strip():
                        f["code_sample"] = code_sample.strip()
            if meta:
                self._append_llm_call(agg, meta)
        return findings

    def _collect_findings(self, agg: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        def redact_secret(value: Any) -> str:
            s = "" if value is None else str(value)
            s = s.strip()
            if not s:
                return ""
            if len(s) <= 2:
                return "***"
            if len(s) <= 6:
                return s[0] + "***" + s[-1]
            return s[:2] + "***" + s[-2:]

        for entry in agg.get("results", []):
            tool = entry.get("tool")
            data = entry.get("data", {})
            if entry.get("skipped") or not entry.get("success"):
                continue
            # Nmap open ports as INFO findings
            if tool == "nmap":
                for host in data.get("scan_data", {}).get("hosts", []):
                    for p in host.get("ports", []):
                        findings.append({
                            "severity": "INFO",
                            "title": f"Open port {p.get('port')}/{p.get('protocol','')}",
                            "evidence": f"{p.get('service','')} {p.get('product','')} {p.get('version','')}".strip(),
                            "tool": "nmap",
                        })
            # Nuclei vulnerabilities
            if tool == "nuclei":
                for f in data.get("findings", []):
                    findings.append({
                        "severity": f.get("severity", "").upper() or "INFO",
                        "title": f.get("name", f.get("id", "nuclei finding")),
                        "evidence": f.get("matched_at", ""),
                        "tool": "nuclei",
                        "type": f.get("type"),
                    })
            # Sqlmap detected injectable parameters
            if tool == "sqlmap":
                for f in data.get("findings", []):
                    findings.append({
                        "severity": "HIGH",
                        "title": "SQL Injection",
                        "evidence": f.get("detail", ""),
                        "tool": "sqlmap",
                    })
            # Hydra valid credentials (high risk)
            if tool == "hydra":
                for c in data.get("found_credentials", []) or []:
                    if not isinstance(c, dict):
                        continue
                    svc = (c.get("service") or data.get("service") or "").strip().lower() or "service"
                    host = (c.get("host") or data.get("target") or "").strip() or "host"
                    port = (c.get("port") or "").strip()
                    login = (c.get("login") or "").strip()
                    password = redact_secret(c.get("password"))
                    where = f"{svc}://{host}"
                    if port:
                        where = f"{where}:{port}"
                    findings.append({
                        "severity": "HIGH",
                        "title": "Valid credentials discovered (bruteforce)",
                        "evidence": f"{where} login={login} password={password}".strip(),
                        "tool": "hydra",
                    })
            # Trivy container CVEs
            if tool == "trivy":
                for f in data.get("findings", []):
                    findings.append({
                        "severity": f.get("severity", "INFO"),
                        "title": f.get("id", "CVE"),
                        "evidence": f.get("pkg", ""),
                        "recommendation": f.get("fixed", ""),
                        "tool": "trivy",
                    })
            # sslscan weak protocols
            if tool == "sslscan":
                weak = data.get("scan_data", {}).get("weak_protocols_enabled", [])
                if isinstance(weak, list):
                    for proto in weak[:10]:
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "Weak TLS protocol enabled",
                            "evidence": str(proto),
                            "tool": "sslscan",
                        })
            # Gobuster paths
            if tool == "gobuster":
                for path in data.get("findings", []):
                    findings.append({
                        "severity": "INFO",
                        "title": "Discovered path",
                        "evidence": path,
                        "tool": "gobuster",
                    })
            # WhatWeb tech stack
            if tool == "whatweb":
                for entry in data.get("scan_data", []):
                    plugins = entry.get("plugins", {})
                    tech = ", ".join(plugins.keys()) if isinstance(plugins, dict) else str(plugins)
                    findings.append({
                        "severity": "INFO",
                        "title": "Tech stack detected",
                        "evidence": tech,
                        "tool": "whatweb",
                    })
            # Supabase RLS check
            if tool == "supabase_rls":
                if data.get("risk"):
                    findings.append({
                        "severity": "HIGH",
                        "title": "Supabase RLS may be disabled",
                        "evidence": f"Unauthenticated request returned HTTP {data.get('status')}",
                        "recommendation": "Enable RLS and verify policies for affected tables/views.",
                        "tool": "supabase_rls",
                    })
        return findings

    def _nmap_args_for_mode(self, mode: str) -> str:
        if mode == "stealth":
            return "-sS -T2"
        if mode == "aggressive":
            return "-sV -O -T4"
        return "-sV -O"

    def _normalize_target(self, target: str) -> Dict[str, Any]:
        """
        Returns:
          - scan_host: host/IP for nmap
          - base_url: base URL for web tooling if target is a URL
          - sqlmap_url: full URL (only when it contains query params)
        """
        if "://" not in target:
            return {"scan_host": target, "base_url": None, "sqlmap_url": None}
        parsed = urlparse(target)
        host = parsed.hostname or target
        netloc = parsed.netloc
        base = f"{parsed.scheme}://{netloc}" if parsed.scheme and netloc else None
        sqlmap_url = target if "?" in target else None
        return {"scan_host": host, "base_url": base, "sqlmap_url": sqlmap_url}

    def _web_targets_from_nmap(self, scan_host: str, nmap_data: Dict[str, Any]) -> List[str]:
        urls: List[str] = []
        prefer_host = scan_host if "/" not in scan_host else None
        for host in nmap_data.get("hosts", []):
            host_id = prefer_host or host.get("ip")
            if not host_id:
                continue
            for p in host.get("ports", []):
                port = p.get("port")
                state = p.get("state")
                service = str(p.get("service") or "").lower()
                if state != "open":
                    continue
                if port is None:
                    continue

                is_http = "http" in service
                if not is_http and port not in (80, 443, 8080, 8443):
                    continue

                scheme = "http"
                if "https" in service or "ssl" in service or port in (443, 8443):
                    scheme = "https"
                if port in (80, 443):
                    urls.append(f"{scheme}://{host_id}")
                else:
                    urls.append(f"{scheme}://{host_id}:{port}")
            if prefer_host:
                break
        # Prefer https first
        urls = sorted(set(urls), key=lambda u: (not u.startswith("https://"), u))
        return urls

    def run(
        self,
        target: str,
        output: Optional[Path],
        container_image: Optional[str] = None,
        mode: str = "normal",
        nuclei_rate_limit: int = 0,
        gobuster_threads: int = 10,
        gobuster_wordlist: Optional[str] = None,
        run_nikto: bool = False,
        run_hydra: bool = False,
        hydra_usernames: Optional[str] = None,
        hydra_passwords: Optional[str] = None,
        hydra_services: Optional[str] = None,
        hydra_threads: int = 4,
        hydra_options: Optional[str] = None,
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
        cancel_event: Optional[Event] = None,
        progress_cb: Optional[Any] = None,
        parallel_web: bool = False,
        max_workers: int = 3,
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

        nuclei_rate_limit, gobuster_threads, max_workers, caps_meta = apply_aggressive_caps(
            mode,
            config=cfg_dict,
            nuclei_rate_limit=nuclei_rate_limit,
            gobuster_threads=gobuster_threads,
            max_workers=max_workers,
        )

        agg: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "scan_host": scan_host,
            "results": [],
            "mode": mode,
            "started_at": time.time(),
            "tuning": {
                "nuclei_rate_limit": nuclei_rate_limit or None,
                "gobuster_threads": gobuster_threads,
                "gobuster_wordlist": gobuster_wordlist,
                "nikto_enabled": bool(run_nikto),
                "hydra_enabled": bool(run_hydra),
                "hydra_services": hydra_services,
                "hydra_threads": int(hydra_threads),
            },
            "safety": {"aggressive_caps": caps_meta},
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

        def run_nmap() -> Dict[str, Any]:
            return self._run_tool_if_enabled(
                "nmap",
                lambda: self.scanners["nmap"].scan(
                    scan_host,
                    arguments=self._nmap_args_for_mode(mode),
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("nmap"),
                ),
            )

        def run_hydra_from_nmap(nmap_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
            if not run_hydra:
                return []
            if not hydra_usernames or not hydra_passwords:
                return [self._skip_tool("hydra", "Missing --hydra-usernames/--hydra-passwords")]
            if not self._has_scanner("hydra"):
                return [self._skip_tool("hydra", "Scanner not available")]
            if not nmap_entry or not nmap_entry.get("success"):
                return [self._skip_tool("hydra", "No nmap results to derive services/ports")]

            services = hydra_services or "ssh,ftp"
            service_list = [s.strip().lower() for s in str(services).replace(";", ",").split(",") if s.strip()]
            if not service_list:
                service_list = ["ssh", "ftp"]

            scan_data = nmap_entry.get("data", {}).get("scan_data", {})
            ports_by_service: Dict[str, List[int]] = {s: [] for s in service_list}
            for host in (scan_data or {}).get("hosts", []) or []:
                for p in host.get("ports", []) or []:
                    try:
                        if str(p.get("state", "")).lower() != "open":
                            continue
                        svc = str(p.get("service", "")).strip().lower()
                        port = int(p.get("port"))
                        if svc in ports_by_service:
                            ports_by_service[svc].append(port)
                    except Exception:
                        continue

            results: List[Dict[str, Any]] = []
            for svc in service_list:
                ports = sorted(set(ports_by_service.get(svc, []) or []))
                if not ports:
                    results.append(self._skip_tool("hydra", f"No {svc} service detected by nmap"))
                    continue
                for port in ports[:2]:
                    extra = hydra_options or ""
                    opt = f"-s {port} -t {int(hydra_threads)} {extra}".strip()
                    note("tool_start", "hydra", f"Running hydra ({svc}) on port {port}")
                    results.append(
                        self._run_tool(
                            "hydra",
                            lambda svc=svc, port=port, opt=opt: self.scanners["hydra"].run(
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
                    note("tool_end", "hydra", f"Finished hydra ({svc}) on port {port}")
                    if canceled():
                        return results
            return results

        def run_web_tools(web_target: str) -> List[Dict[str, Any]]:
            if not parallel_web:
                # Sequential (default)
                results: List[Dict[str, Any]] = []
                note("tool_start", "whatweb", "Running whatweb")
                whatweb_entry = self._run_tool_if_enabled(
                    "whatweb",
                    lambda: self.scanners["whatweb"].scan(
                        web_target,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("whatweb"),
                    ),
                )
                note("tool_end", "whatweb", "Finished whatweb")
                results.append(whatweb_entry)
                if canceled() or (isinstance(whatweb_entry.get("data"), dict) and whatweb_entry["data"].get("canceled")):
                    return results

                note("tool_start", "nuclei", "Running nuclei")
                nuclei_entry = self._run_tool_if_enabled(
                    "nuclei",
                    lambda: self.scanners["nuclei"].scan(
                        web_target,
                        rate_limit=nuclei_rate_limit or None,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("nuclei"),
                    ),
                )
                note("tool_end", "nuclei", "Finished nuclei")
                results.append(nuclei_entry)
                if canceled() or (isinstance(nuclei_entry.get("data"), dict) and nuclei_entry["data"].get("canceled")):
                    return results

                note("tool_start", "gobuster", "Running gobuster")
                if gobuster_wordlist:
                    gobuster_entry = self._run_tool_if_enabled(
                        "gobuster",
                        lambda: self.scanners["gobuster"].scan(
                            web_target,
                            wordlist=gobuster_wordlist,
                            threads=gobuster_threads,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("gobuster"),
                        ),
                    )
                else:
                    gobuster_entry = self._run_tool_if_enabled(
                        "gobuster",
                        lambda: self.scanners["gobuster"].scan(
                            web_target,
                            threads=gobuster_threads,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("gobuster"),
                        ),
                    )
                note("tool_end", "gobuster", "Finished gobuster")
                results.append(gobuster_entry)
                return results

            # Parallel web tooling
            futures = {}
            results: List[Dict[str, Any]] = []
            max_w = max(1, min(int(max_workers), 8))
            with ThreadPoolExecutor(max_workers=max_w) as ex:
                note("tool_start", "whatweb", "Running whatweb")
                if self._tool_enabled("whatweb", default=True):
                    futures[
                        ex.submit(
                            self._run_tool,
                            "whatweb",
                            lambda: self.scanners["whatweb"].scan(
                                web_target,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("whatweb"),
                            ),
                        )
                    ] = "whatweb"
                else:
                    results.append(self._skip_disabled("whatweb"))
                note("tool_start", "nuclei", "Running nuclei")
                if self._tool_enabled("nuclei", default=True):
                    futures[
                        ex.submit(
                            self._run_tool,
                            "nuclei",
                            lambda: self.scanners["nuclei"].scan(
                                web_target,
                                rate_limit=nuclei_rate_limit or None,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("nuclei"),
                            ),
                        )
                    ] = "nuclei"
                else:
                    results.append(self._skip_disabled("nuclei"))
                note("tool_start", "gobuster", "Running gobuster")
                if gobuster_wordlist:
                    if self._tool_enabled("gobuster", default=True):
                        futures[
                            ex.submit(
                                self._run_tool,
                                "gobuster",
                                lambda: self.scanners["gobuster"].scan(
                                    web_target,
                                    wordlist=gobuster_wordlist,
                                    threads=gobuster_threads,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("gobuster"),
                                ),
                            )
                        ] = "gobuster"
                    else:
                        results.append(self._skip_disabled("gobuster"))
                else:
                    if self._tool_enabled("gobuster", default=True):
                        futures[
                            ex.submit(
                                self._run_tool,
                                "gobuster",
                                lambda: self.scanners["gobuster"].scan(
                                    web_target,
                                    threads=gobuster_threads,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("gobuster"),
                                ),
                            )
                        ] = "gobuster"
                    else:
                        results.append(self._skip_disabled("gobuster"))

                for fut in as_completed(futures):
                    tool = futures.get(fut, "tool")
                    try:
                        entry = fut.result()
                    except Exception as e:
                        entry = {"tool": tool, "success": False, "error": str(e)}
                    results.append(entry)
                    note("tool_end", tool, f"Finished {tool}")
            return results

        # Recon & web scans (optional parallel overlap)
        nmap_entry: Optional[Dict[str, Any]] = None
        web_targets: List[str] = []
        if normalized["base_url"]:
            web_targets = [normalized["base_url"]]
        agg["web_targets"] = web_targets

        llm_enabled = bool(use_llm) and self._llm_enabled(default=True)
        if not llm_enabled:
            agg["llm"] = {"enabled": False, "reason": "Disabled by config or --no-llm", "calls": []}

        if canceled():
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            return agg

        if parallel_web and web_targets:
            # Overlap nmap with web tools when URL is provided
            web_target = web_targets[0]
            max_w = max(1, min(int(max_workers), 8))
            with ThreadPoolExecutor(max_workers=max_w) as ex:
                note("tool_start", "nmap", f"Running nmap ({mode})")
                nmap_future = ex.submit(run_nmap)
                web_future = ex.submit(run_web_tools, web_target)

                nmap_entry = nmap_future.result()
                agg["results"].append(nmap_entry)
                note("tool_end", "nmap", "Finished nmap")

                for entry in web_future.result():
                    agg["results"].append(entry)

            if nmap_entry and nmap_entry.get("success"):
                open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {}))
                agg["open_ports"] = open_ports
                for entry in run_hydra_from_nmap(nmap_entry):
                    agg["results"].append(entry)

                if self._should_run_dnsenum(scan_host):
                    if self._has_scanner("dnsenum"):
                        note("tool_start", "dnsenum", "Running dnsenum")
                        agg["results"].append(
                            self._run_tool_if_enabled(
                                "dnsenum",
                                lambda: self.scanners["dnsenum"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("dnsenum"),
                                ),
                            )
                        )
                        note("tool_end", "dnsenum", "Finished dnsenum")
                    else:
                        agg["results"].append(self._skip_tool("dnsenum", "Scanner not available"))
                else:
                    agg["results"].append(self._skip_tool("dnsenum", "Not a domain target"))

                tls_ports = [p for p in open_ports if p in (443, 8443)]
                if tls_ports:
                    if self._has_scanner("sslscan"):
                        for p in tls_ports[:2]:
                            note("tool_start", "sslscan", f"Running sslscan on port {p}")
                            agg["results"].append(
                                self._run_tool_if_enabled(
                                    "sslscan",
                                    lambda p=p: self.scanners["sslscan"].scan(
                                        scan_host,
                                        port=p,
                                        cancel_event=cancel_event,
                                        timeout_seconds=self._tool_timeout_seconds("sslscan"),
                                    ),
                                )
                            )
                            note("tool_end", "sslscan", f"Finished sslscan on port {p}")
                    else:
                        agg["results"].append(self._skip_tool("sslscan", "Scanner not available"))
                else:
                    agg["results"].append(self._skip_tool("sslscan", "No TLS ports detected (443/8443)"))

                if any(p in (139, 445) for p in open_ports):
                    if self._has_scanner("enum4linux-ng"):
                        note("tool_start", "enum4linux-ng", "Running enum4linux-ng")
                        agg["results"].append(
                            self._run_tool_if_enabled(
                                "enum4linux-ng",
                                lambda: self.scanners["enum4linux-ng"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("enum4linux-ng"),
                                ),
                            )
                        )
                        note("tool_end", "enum4linux-ng", "Finished enum4linux-ng")
                    else:
                        agg["results"].append(self._skip_tool("enum4linux-ng", "Scanner not available"))
                else:
                    agg["results"].append(self._skip_tool("enum4linux-ng", "No SMB ports detected (139/445)"))

            if run_nikto:
                if self._has_scanner("nikto"):
                    try:
                        u = urlparse(web_target)
                        host = u.hostname or scan_host
                        port = int(u.port or (443 if (u.scheme or "").lower() == "https" else 80))
                    except Exception:
                        host = scan_host
                        port = 80
                    note("tool_start", "nikto", "Running nikto")
                    agg["results"].append(
                        self._run_tool_if_enabled(
                            "nikto",
                            lambda: self.scanners["nikto"].scan(
                                host,
                                port=port,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("nikto"),
                            ),
                        )
                    )
                    note("tool_end", "nikto", "Finished nikto")
                else:
                    agg["results"].append(self._skip_tool("nikto", "Scanner not available"))

        else:
            # Run nmap first (required to discover web targets)
            note("tool_start", "nmap", f"Running nmap ({mode})")
            nmap_entry = run_nmap()
            agg["results"].append(nmap_entry)
            note("tool_end", "nmap", "Finished nmap")

            if canceled() or (isinstance(nmap_entry.get("data"), dict) and nmap_entry["data"].get("canceled")):
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg

            if not web_targets and nmap_entry.get("success"):
                web_targets = self._web_targets_from_nmap(scan_host, nmap_entry.get("data", {}).get("scan_data", {}))
                agg["web_targets"] = web_targets

            # Post-recon conditional modules
            if nmap_entry.get("success"):
                open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {}))
                agg["open_ports"] = open_ports
                for entry in run_hydra_from_nmap(nmap_entry):
                    agg["results"].append(entry)

                # DNS enumeration (domain targets)
                if self._should_run_dnsenum(scan_host):
                    if self._has_scanner("dnsenum"):
                        note("tool_start", "dnsenum", "Running dnsenum")
                        agg["results"].append(
                            self._run_tool_if_enabled(
                                "dnsenum",
                                lambda: self.scanners["dnsenum"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("dnsenum"),
                                ),
                            )
                        )
                        note("tool_end", "dnsenum", "Finished dnsenum")
                    else:
                        agg["results"].append(self._skip_tool("dnsenum", "Scanner not available"))
                else:
                    agg["results"].append(self._skip_tool("dnsenum", "Not a domain target"))

                # TLS scan (https ports)
                tls_ports = [p for p in open_ports if p in (443, 8443)]
                if tls_ports:
                    if self._has_scanner("sslscan"):
                        for p in tls_ports[:2]:
                            note("tool_start", "sslscan", f"Running sslscan on port {p}")
                            agg["results"].append(
                                self._run_tool_if_enabled(
                                    "sslscan",
                                    lambda p=p: self.scanners["sslscan"].scan(
                                        scan_host,
                                        port=p,
                                        cancel_event=cancel_event,
                                        timeout_seconds=self._tool_timeout_seconds("sslscan"),
                                    ),
                                )
                            )
                            note("tool_end", "sslscan", f"Finished sslscan on port {p}")
                    else:
                        agg["results"].append(self._skip_tool("sslscan", "Scanner not available"))
                else:
                    agg["results"].append(self._skip_tool("sslscan", "No TLS ports detected (443/8443)"))

                # SMB enumeration
                if any(p in (139, 445) for p in open_ports):
                    if self._has_scanner("enum4linux-ng"):
                        note("tool_start", "enum4linux-ng", "Running enum4linux-ng")
                        agg["results"].append(
                            self._run_tool_if_enabled(
                                "enum4linux-ng",
                                lambda: self.scanners["enum4linux-ng"].scan(
                                    scan_host,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("enum4linux-ng"),
                                ),
                            )
                        )
                        note("tool_end", "enum4linux-ng", "Finished enum4linux-ng")
                    else:
                        agg["results"].append(self._skip_tool("enum4linux-ng", "Scanner not available"))
                else:
                    agg["results"].append(self._skip_tool("enum4linux-ng", "No SMB ports detected (139/445)"))

            if web_targets:
                for entry in run_web_tools(web_targets[0]):
                    agg["results"].append(entry)
                if run_nikto:
                    if self._has_scanner("nikto"):
                        try:
                            u = urlparse(web_targets[0])
                            host = u.hostname or scan_host
                            port = int(u.port or (443 if (u.scheme or "").lower() == "https" else 80))
                        except Exception:
                            host = scan_host
                            port = 80
                        note("tool_start", "nikto", "Running nikto")
                        agg["results"].append(
                            self._run_tool_if_enabled(
                                "nikto",
                                lambda: self.scanners["nikto"].scan(
                                    host,
                                    port=port,
                                    cancel_event=cancel_event,
                                    timeout_seconds=self._tool_timeout_seconds("nikto"),
                                ),
                            )
                        )
                        note("tool_end", "nikto", "Finished nikto")
                    else:
                        agg["results"].append(self._skip_tool("nikto", "Scanner not available"))
            else:
                agg["results"].append(self._skip_tool("whatweb", "No web ports detected (80/443/8080/8443)"))
                agg["results"].append(self._skip_tool("nuclei", "No web ports detected (80/443/8080/8443)"))
                agg["results"].append(self._skip_tool("gobuster", "No web ports detected (80/443/8080/8443)"))
                agg["results"].append(self._skip_tool("nikto", "No web ports detected (80/443/8080/8443)"))

        if normalized["sqlmap_url"]:
            if canceled():
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg
            note("tool_start", "sqlmap", "Running sqlmap")
            sqlmap_entry = self._run_tool_if_enabled(
                "sqlmap",
                lambda: self.scanners["sqlmap"].scan(
                    normalized["sqlmap_url"],
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("sqlmap"),
                ),
            )
            agg["results"].append(sqlmap_entry)
            note("tool_end", "sqlmap", "Finished sqlmap")
            if canceled() or (isinstance(sqlmap_entry.get("data"), dict) and sqlmap_entry["data"].get("canceled")):
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg
        else:
            agg["results"].append(self._skip_tool("sqlmap", "No parameterized URL provided (include '?' in target URL)"))

        # Supabase RLS heuristic (only for supabase-like URLs)
        supabase_url = None
        for u in web_targets:
            if "supabase" in u:
                supabase_url = u
                break
        if supabase_url:
            if canceled():
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg
            note("tool_start", "supabase_rls", "Running supabase RLS check")
            agg["results"].append(
                self._run_tool_if_enabled(
                    "supabase_rls",
                    lambda: self.scanners["supabase_rls"].check(
                        supabase_url,
                        timeout_seconds=self._tool_timeout_seconds("supabase_rls"),
                    ),
                )
            )
            note("tool_end", "supabase_rls", "Finished supabase RLS check")

        if container_image:
            if canceled():
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg
            note("tool_start", "trivy", "Running trivy")
            trivy_entry = self._run_tool_if_enabled(
                "trivy",
                lambda: self.scanners["trivy"].scan(
                    container_image,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("trivy"),
                ),
            )
            agg["results"].append(trivy_entry)
            note("tool_end", "trivy", "Finished trivy")
            if canceled() or (isinstance(trivy_entry.get("data"), dict) and trivy_entry["data"].get("canceled")):
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg

        # Stable ordering: when parallel web tools are used, as_completed() appends results in
        # completion order which is non-deterministic; sort for predictable reporting.
        if parallel_web:
            try:
                agg["results"] = stable_sort_results(agg.get("results", []))
            except Exception:
                pass

        if canceled():
            agg["canceled"] = True
            agg["finished_at"] = time.time()
            return agg
        if llm_enabled:
            note("llm_start", "summary", "Summarizing with LLM")
            summary, llm_meta = self._summarize_with_llm(agg)
            if llm_meta:
                self._append_llm_call(agg, llm_meta)
            if summary:
                agg["summary"] = summary
        else:
            if remediate:
                agg.setdefault("llm", {})["remediation_skipped"] = True

        findings = self._collect_findings(agg)
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
                logger.error(f"Failed to write audit report: {e}")
                agg["saved_to"] = None
                agg["write_error"] = str(e)
        else:
            agg["saved_to"] = None

        return agg
