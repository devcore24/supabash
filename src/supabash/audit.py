import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    WhatWebScanner,
    NucleiScanner,
    GobusterScanner,
    SqlmapScanner,
    TrivyScanner,
    SupabaseRLSChecker,
)
from supabash.llm import LLMClient
from supabash import prompts
from supabash.llm_context import prepare_json_payload

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
            "trivy": TrivyScanner(),
            "supabase_rls": SupabaseRLSChecker(),
        }
        self.llm = llm_client or LLMClient()

    def _run_tool(self, name: str, func) -> Dict[str, Any]:
        try:
            result = func()
            success = result.get("success", False)
            return {"tool": name, "success": success, "data": result}
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
                if state != "open":
                    continue
                if port not in (80, 443, 8080, 8443):
                    continue
                scheme = "https" if port in (443, 8443) else "http"
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
        remediate: bool = False,
        max_remediations: int = 5,
        min_remediation_severity: str = "MEDIUM",
    ) -> Dict[str, Any]:
        normalized = self._normalize_target(target)
        scan_host = normalized["scan_host"]

        agg: Dict[str, Any] = {
            "target": target,
            "scan_host": scan_host,
            "results": [],
            "mode": mode,
            "tuning": {
                "nuclei_rate_limit": nuclei_rate_limit or None,
                "gobuster_threads": gobuster_threads,
                "gobuster_wordlist": gobuster_wordlist,
            },
        }
        if container_image:
            agg["container_image"] = container_image

        # Recon & web scans
        nmap_entry = self._run_tool("nmap", lambda: self.scanners["nmap"].scan(scan_host, arguments=self._nmap_args_for_mode(mode)))
        agg["results"].append(nmap_entry)

        web_targets: List[str] = []
        if normalized["base_url"]:
            web_targets = [normalized["base_url"]]
        elif nmap_entry.get("success"):
            web_targets = self._web_targets_from_nmap(scan_host, nmap_entry.get("data", {}).get("scan_data", {}))
        agg["web_targets"] = web_targets

        if web_targets:
            web_target = web_targets[0]
            agg["results"].append(self._run_tool("whatweb", lambda: self.scanners["whatweb"].scan(web_target)))
            agg["results"].append(self._run_tool("nuclei", lambda: self.scanners["nuclei"].scan(web_target, rate_limit=nuclei_rate_limit or None)))
            if gobuster_wordlist:
                agg["results"].append(self._run_tool("gobuster", lambda: self.scanners["gobuster"].scan(web_target, wordlist=gobuster_wordlist, threads=gobuster_threads)))
            else:
                agg["results"].append(self._run_tool("gobuster", lambda: self.scanners["gobuster"].scan(web_target, threads=gobuster_threads)))
        else:
            agg["results"].append(self._skip_tool("whatweb", "No web ports detected (80/443/8080/8443)"))
            agg["results"].append(self._skip_tool("nuclei", "No web ports detected (80/443/8080/8443)"))
            agg["results"].append(self._skip_tool("gobuster", "No web ports detected (80/443/8080/8443)"))

        if normalized["sqlmap_url"]:
            agg["results"].append(self._run_tool("sqlmap", lambda: self.scanners["sqlmap"].scan(normalized["sqlmap_url"])))
        else:
            agg["results"].append(self._skip_tool("sqlmap", "No parameterized URL provided (include '?' in target URL)"))

        # Supabase RLS heuristic (only for supabase-like URLs)
        supabase_url = None
        for u in web_targets:
            if "supabase" in u:
                supabase_url = u
                break
        if supabase_url:
            agg["results"].append(self._run_tool("supabase_rls", lambda: self.scanners["supabase_rls"].check(supabase_url)))

        if container_image:
            agg["results"].append(
                self._run_tool("trivy", lambda: self.scanners["trivy"].scan(container_image))
            )

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
