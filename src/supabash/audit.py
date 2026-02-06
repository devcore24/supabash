import json
import ipaddress
import os
import hashlib
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
import time
from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    WhatWebScanner,
    HttpxScanner,
    NucleiScanner,
    GobusterScanner,
    FfufScanner,
    KatanaScanner,
    SqlmapScanner,
    HydraRunner,
    NiktoScanner,
    SslscanScanner,
    DnsenumScanner,
    Enum4linuxNgScanner,
    SubfinderScanner,
    TrivyScanner,
    SupabaseAuditScanner,
    SearchsploitScanner,
    WPScanScanner,
    TheHarvesterScanner,
    NetdiscoverScanner,
    AircrackNgScanner,
    CrackMapExecScanner,
    MedusaRunner,
    ScoutSuiteScanner,
    ProwlerScanner,
)
from supabash.llm import LLMClient
from supabash import prompts
from supabash.llm_context import prepare_json_payload
from supabash.report_order import stable_sort_results
from supabash.report_schema import SCHEMA_VERSION, annotate_schema_validation
from supabash.aggressive_caps import apply_aggressive_caps

logger = setup_logger(__name__)

COMPLIANCE_PROFILE_ALIASES = {
    "pci": "compliance_pci",
    "pci_dss": "compliance_pci",
    "pci-dss": "compliance_pci",
    "soc2": "compliance_soc2",
    "soc_2": "compliance_soc2",
    "soc-2": "compliance_soc2",
    "iso": "compliance_iso",
    "iso27001": "compliance_iso",
    "iso-27001": "compliance_iso",
    "dora": "compliance_dora",
    "nis2": "compliance_nis2",
    "nis-2": "compliance_nis2",
    "gdpr": "compliance_gdpr",
    "bsi": "compliance_bsi",
}

COMPLIANCE_PROFILES = {
    "compliance_pci": {
        "label": "PCI-DSS 4.0",
        "focus": "Cardholder data environment controls with emphasis on strong cryptography and vulnerability management.",
        "preferred_tools": ["sslscan", "nuclei", "whatweb", "httpx", "sqlmap"],
        "rate_limit": 10,
        "threads": 10,
        "required_tools": ["sslscan"],
    },
    "compliance_soc2": {
        "label": "SOC 2 Type II",
        "focus": "Security and availability controls with evidence of exposure management and vulnerability assessment.",
        "preferred_tools": ["nuclei", "whatweb", "httpx", "sslscan"],
        "rate_limit": 10,
        "threads": 10,
        "required_tools": [],
    },
    "compliance_iso": {
        "label": "ISO/IEC 27001",
        "focus": "Information security controls with structured evidence of vulnerability management and secure configuration.",
        "preferred_tools": ["nuclei", "whatweb", "httpx", "sslscan"],
        "rate_limit": 10,
        "threads": 10,
        "required_tools": [],
    },
    "compliance_dora": {
        "label": "DORA",
        "focus": "Operational resilience with emphasis on vulnerability detection and service exposure.",
        "preferred_tools": ["nuclei", "whatweb", "httpx", "sslscan"],
        "rate_limit": 8,
        "threads": 8,
        "required_tools": [],
    },
    "compliance_nis2": {
        "label": "NIS2",
        "focus": "Risk management and exposure reduction for critical services.",
        "preferred_tools": ["nuclei", "whatweb", "httpx", "sslscan"],
        "rate_limit": 8,
        "threads": 8,
        "required_tools": [],
    },
    "compliance_gdpr": {
        "label": "GDPR",
        "focus": "Data protection and exposure risk indicators for externally reachable services.",
        "preferred_tools": ["whatweb", "httpx", "gobuster", "nuclei", "sqlmap"],
        "rate_limit": 10,
        "threads": 10,
        "required_tools": [],
    },
    "compliance_bsi": {
        "label": "BSI IT-Grundschutz",
        "focus": "Baseline security controls with evidence of secure configuration and vulnerability management.",
        "preferred_tools": ["nuclei", "whatweb", "httpx", "sslscan"],
        "rate_limit": 10,
        "threads": 10,
        "required_tools": [],
    },
}

COMPLIANCE_CONTROL_REFERENCES = {
    "crypto": {
        "compliance_pci": "PCI-DSS 4.0 Req 4.2 (Strong Cryptography)",
        "compliance_soc2": "SOC 2 CC6.7 (Encryption Controls)",
        "compliance_iso": "ISO/IEC 27001 A.10.1 (Cryptographic Controls)",
        "compliance_dora": "DORA ICT Risk Mgmt (Security of Data in Transit)",
        "compliance_nis2": "NIS2 Risk Mgmt (Network Security Measures)",
        "compliance_gdpr": "GDPR Art. 32 (Encryption of Personal Data)",
        "compliance_bsi": "BSI IT-Grundschutz: Cryptographic Safeguards",
    },
    "vuln_mgmt": {
        "compliance_pci": "PCI-DSS 4.0 Req 11.3 (Vulnerability Management)",
        "compliance_soc2": "SOC 2 CC7.1 (Vulnerability Management)",
        "compliance_iso": "ISO/IEC 27001 A.12.6 (Technical Vulnerability Management)",
        "compliance_dora": "DORA ICT Risk Mgmt (Vulnerability Handling)",
        "compliance_nis2": "NIS2 Risk Mgmt (Vulnerability Handling)",
        "compliance_gdpr": "GDPR Art. 32 (Security of Processing)",
        "compliance_bsi": "BSI IT-Grundschutz: Vulnerability Management",
    },
    "access_control": {
        "compliance_pci": "PCI-DSS 4.0 Req 8 (Access Control)",
        "compliance_soc2": "SOC 2 CC6.1 (Logical Access)",
        "compliance_iso": "ISO/IEC 27001 A.9 (Access Control)",
        "compliance_dora": "DORA ICT Risk Mgmt (Access Control)",
        "compliance_nis2": "NIS2 Risk Mgmt (Access Control)",
        "compliance_gdpr": "GDPR Art. 32 (Access Control)",
        "compliance_bsi": "BSI IT-Grundschutz: Access Control",
    },
    "data_protection": {
        "compliance_pci": "PCI-DSS 4.0 Req 3 (Protect Stored Account Data)",
        "compliance_soc2": "SOC 2 CC6.8 (Data Classification & Protection)",
        "compliance_iso": "ISO/IEC 27001 A.8 (Asset Management)",
        "compliance_dora": "DORA ICT Risk Mgmt (Data Protection)",
        "compliance_nis2": "NIS2 Risk Mgmt (Data Protection)",
        "compliance_gdpr": "GDPR Art. 5/32 (Data Protection)",
        "compliance_bsi": "BSI IT-Grundschutz: Data Protection",
    },
}

EVIDENCE_VERSION_COMMANDS: Dict[str, List[List[str]]] = {
    "nmap": [["nmap", "--version"]],
    "httpx": [["httpx", "-version"], ["httpx", "--version"]],
    "whatweb": [["whatweb", "--version"]],
    "nuclei": [["nuclei", "-version"], ["nuclei", "--version"]],
    "gobuster": [["gobuster", "version"], ["gobuster", "--version"]],
    "ffuf": [["ffuf", "-V"], ["ffuf", "--version"]],
    "katana": [["katana", "-version"], ["katana", "--version"]],
    "sqlmap": [["sqlmap", "--version"]],
    "sslscan": [["sslscan", "--version"]],
    "dnsenum": [["dnsenum", "--help"]],
    "subfinder": [["subfinder", "-version"], ["subfinder", "--version"]],
    "trivy": [["trivy", "--version"]],
    "wpscan": [["wpscan", "--version"]],
    "hydra": [["hydra", "-h"]],
    "medusa": [["medusa", "-h"]],
    "nikto": [["nikto", "-Version"]],
}


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
            "httpx": HttpxScanner(),
            "nuclei": NucleiScanner(),
            "gobuster": GobusterScanner(),
            "ffuf": FfufScanner(),
            "katana": KatanaScanner(),
            "sqlmap": SqlmapScanner(),
            "hydra": HydraRunner(),
            "nikto": NiktoScanner(),
            "sslscan": SslscanScanner(),
            "dnsenum": DnsenumScanner(),
            "enum4linux-ng": Enum4linuxNgScanner(),
            "subfinder": SubfinderScanner(),
            "trivy": TrivyScanner(),
            "supabase_audit": SupabaseAuditScanner(),
            "searchsploit": SearchsploitScanner(),
            "wpscan": WPScanScanner(),
            "theharvester": TheHarvesterScanner(),
            "netdiscover": NetdiscoverScanner(),
            "aircrack-ng": AircrackNgScanner(),
            "crackmapexec": CrackMapExecScanner(),
            "medusa": MedusaRunner(),
            "scoutsuite": ScoutSuiteScanner(),
            "prowler": ProwlerScanner(),
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

    def _tls_candidate_ports_from_nmap(
        self,
        nmap_data: Dict[str, Any],
        web_targets: Optional[List[str]] = None,
    ) -> List[int]:
        """
        Best-effort TLS candidate detection.

        Includes:
        - Open ports whose nmap service/tunnel hints at TLS/SSL/HTTPS.
        - Common non-standard HTTPS/TLS ports when open.
        - Ports from discovered/explicit https:// web targets.
        """
        candidates: set[int] = set()
        common_tls_ports = {443, 8443, 9443, 10443, 4443, 6443}

        for host in (nmap_data or {}).get("hosts", []) or []:
            for p in host.get("ports", []) or []:
                try:
                    if str(p.get("state", "")).lower() != "open":
                        continue
                    port = int(p.get("port"))
                except Exception:
                    continue

                service = str(p.get("service") or "").strip().lower()
                tunnel = str(p.get("tunnel") or "").strip().lower()
                hint = f"{service} {tunnel}".strip()
                has_tls_hint = any(token in hint for token in ("https", "ssl", "tls"))

                if has_tls_hint or port in common_tls_ports:
                    candidates.add(port)

        if isinstance(web_targets, list):
            for target in web_targets:
                if not isinstance(target, str):
                    continue
                value = target.strip()
                if not value:
                    continue
                try:
                    parsed = urlparse(value)
                    if (parsed.scheme or "").lower() != "https":
                        continue
                    port = int(parsed.port or 443)
                    candidates.add(port)
                except Exception:
                    continue

        return sorted(candidates)

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
        host_l = host.lower()
        if host_l in ("localhost", "localhost.localdomain", "localdomain"):
            return False
        if host_l.endswith(".localhost"):
            return False
        return not self._is_ip_literal(host)

    def _dns_target_skip_reason(self, scan_host: str) -> str:
        host = (scan_host or "").strip()
        if not host:
            return "Not a domain target"
        host_l = host.lower()
        if host_l in ("localhost", "localhost.localdomain", "localdomain") or host_l.endswith(".localhost"):
            return "Localhost/loopback target (DNS enumeration N/A)"
        if self._is_ip_literal(host):
            return "IP target (DNS enumeration N/A)"
        if "/" in host or ":" in host:
            return "Not a domain target"
        return "Not a domain target"

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

    def _normalize_compliance_profile(self, profile: Optional[str]) -> Optional[str]:
        if not profile:
            return None
        token = str(profile).strip().lower()
        if not token:
            return None
        token = token.replace(" ", "_")
        if token in COMPLIANCE_PROFILE_ALIASES:
            return COMPLIANCE_PROFILE_ALIASES[token]
        if token.startswith("compliance_"):
            return token if token in COMPLIANCE_PROFILES else None
        candidate = f"compliance_{token}"
        return candidate if candidate in COMPLIANCE_PROFILES else None

    def _compliance_profiles(self) -> Dict[str, Dict[str, Any]]:
        return COMPLIANCE_PROFILES

    def _compliance_profile_label(self, profile: Optional[str]) -> Optional[str]:
        if not profile:
            return None
        settings = COMPLIANCE_PROFILES.get(profile)
        if not settings:
            return None
        label = settings.get("label")
        return str(label) if label else None

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

    def _safe_filename_fragment(self, value: Any, fallback: str = "item") -> str:
        raw = str(value or "").strip().lower()
        if not raw:
            raw = fallback
        cleaned = re.sub(r"[^a-z0-9._-]+", "_", raw)
        cleaned = cleaned.strip("._-")
        return cleaned or fallback

    def _sha256_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _best_effort_tool_version(self, tool: str) -> Optional[str]:
        commands = EVIDENCE_VERSION_COMMANDS.get(str(tool or "").strip().lower(), [])
        for cmd in commands:
            try:
                out = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )
                text = (out.stdout or out.stderr or "").strip()
                if not text:
                    continue
                first = text.splitlines()[0].strip()
                if first:
                    return first
            except Exception:
                continue
        return None

    def _collect_runtime_metadata(self, agg: Dict[str, Any]) -> Dict[str, Any]:
        runtime: Dict[str, Any] = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "executable": sys.executable,
            "target": agg.get("target"),
            "scan_host": agg.get("scan_host"),
            "compliance_profile": agg.get("compliance_profile"),
            "compliance_framework": agg.get("compliance_framework"),
        }
        llm = agg.get("llm")
        if isinstance(llm, dict):
            providers: List[str] = []
            models: List[str] = []
            calls = llm.get("calls")
            if isinstance(calls, list):
                for c in calls:
                    if not isinstance(c, dict):
                        continue
                    p = c.get("provider")
                    m = c.get("model")
                    if isinstance(p, str) and p.strip() and p.strip() not in providers:
                        providers.append(p.strip())
                    if isinstance(m, str) and m.strip() and m.strip() not in models:
                        models.append(m.strip())
            if providers:
                runtime["llm_providers"] = providers
            if models:
                runtime["llm_models"] = models

        tool_versions: Dict[str, str] = {}
        seen_tools = set()
        for entry in agg.get("results", []) or []:
            if not isinstance(entry, dict):
                continue
            tool = str(entry.get("tool") or "").strip().lower()
            if not tool or tool in seen_tools:
                continue
            seen_tools.add(tool)
            version = self._best_effort_tool_version(tool)
            if isinstance(version, str) and version:
                tool_versions[tool] = version
        if tool_versions:
            runtime["tool_versions"] = tool_versions
        return runtime

    def _write_evidence_pack(self, agg: Dict[str, Any], output: Optional[Path]) -> None:
        if output is None:
            return
        try:
            report_root = output.parent
            evidence_dir = report_root / "evidence" / output.stem
            results_dir = evidence_dir / "results"
            results_dir.mkdir(parents=True, exist_ok=True)

            artifacts: List[Dict[str, Any]] = []
            now = time.time()
            for idx, entry in enumerate(agg.get("results", []) or []):
                if not isinstance(entry, dict):
                    continue
                tool = self._safe_filename_fragment(entry.get("tool"), fallback="tool")
                artifact_name = f"{idx:03d}-{tool}.json"
                artifact_path = results_dir / artifact_name
                payload = {
                    "tool": entry.get("tool"),
                    "status": "skipped"
                    if entry.get("skipped")
                    else ("success" if entry.get("success") else "failed"),
                    "target": entry.get("target"),
                    "command": entry.get("command"),
                    "phase": entry.get("phase"),
                    "reason": entry.get("reason"),
                    "error": entry.get("error"),
                    "fallback_for": entry.get("fallback_for"),
                    "data": entry.get("data"),
                }
                artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                rel_path = str(artifact_path.relative_to(report_root))
                artifacts.append(
                    {
                        "kind": "tool_result",
                        "tool": entry.get("tool"),
                        "status": payload["status"],
                        "path": rel_path,
                        "sha256": self._sha256_file(artifact_path),
                        "bytes": artifact_path.stat().st_size,
                        "created_at": now,
                    }
                )

            runtime = self._collect_runtime_metadata(agg)
            manifest = {
                "version": 1,
                "generated_at": now,
                "report_file": str(output.name),
                "artifact_count": len(artifacts),
                "runtime": runtime,
                "artifacts": artifacts,
            }
            manifest_path = evidence_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            agg["evidence_pack"] = {
                "dir": str(evidence_dir.relative_to(report_root)),
                "manifest": str(manifest_path.relative_to(report_root)),
                "artifact_count": len(artifacts),
                "runtime": runtime,
            }
        except Exception as e:
            agg["evidence_pack_error"] = str(e)

    def _whatweb_detects_wordpress(self, whatweb_entry: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(whatweb_entry, dict):
            return False
        data = whatweb_entry.get("data", {})
        if not isinstance(data, dict):
            return False
        scan_data = data.get("scan_data", [])
        if not isinstance(scan_data, list):
            return False
        for item in scan_data:
            if not isinstance(item, dict):
                continue
            plugins = item.get("plugins", {})
            if isinstance(plugins, dict):
                for key in plugins.keys():
                    if "wordpress" in str(key).lower():
                        return True
            banner = item.get("banner")
            if isinstance(banner, str) and "wordpress" in banner.lower():
                return True
        return False

    def _wpscan_args(self) -> Dict[str, Optional[str]]:
        cfg = self._tool_config("wpscan")
        if not isinstance(cfg, dict):
            cfg = {}
        api_token = cfg.get("api_token")
        if isinstance(api_token, str):
            api_token = api_token.strip() or None
        else:
            api_token = None
        enumerate_opt = cfg.get("enumerate") or cfg.get("enumeration")
        if isinstance(enumerate_opt, str):
            enumerate_opt = enumerate_opt.strip() or None
        else:
            enumerate_opt = None
        arguments = cfg.get("arguments")
        if isinstance(arguments, str):
            arguments = arguments.strip() or None
        else:
            arguments = None
        return {"api_token": api_token, "enumerate": enumerate_opt, "arguments": arguments}

    def _theharvester_args(self) -> Dict[str, Any]:
        cfg = self._tool_config("theharvester")
        if not isinstance(cfg, dict):
            cfg = {}
        sources = cfg.get("sources")
        if isinstance(sources, str):
            sources = sources.strip() or None
        else:
            sources = None
        limit = cfg.get("limit")
        try:
            limit = int(limit)
        except Exception:
            limit = None
        start = cfg.get("start")
        try:
            start = int(start)
        except Exception:
            start = None
        arguments = cfg.get("arguments")
        if isinstance(arguments, str):
            arguments = arguments.strip() or None
        else:
            arguments = None
        return {"sources": sources, "limit": limit, "start": start, "arguments": arguments}

    def _scoutsuite_args(self) -> Dict[str, Optional[str]]:
        cfg = self._tool_config("scoutsuite")
        if not isinstance(cfg, dict):
            cfg = {}
        provider = cfg.get("provider")
        if isinstance(provider, str):
            provider = provider.strip() or None
        else:
            provider = None
        arguments = cfg.get("arguments")
        if isinstance(arguments, str):
            arguments = arguments.strip() or None
        else:
            arguments = None
        return {"provider": provider, "arguments": arguments}

    def _prowler_args(self) -> Dict[str, Optional[str]]:
        cfg = self._tool_config("prowler")
        if not isinstance(cfg, dict):
            cfg = {}
        arguments = cfg.get("arguments")
        if isinstance(arguments, str):
            arguments = arguments.strip() or None
        else:
            arguments = None
        return {"arguments": arguments}

    def _aircrack_args(self) -> Dict[str, Optional[str]]:
        cfg = self._tool_config("aircrack-ng")
        if not isinstance(cfg, dict):
            cfg = {}
        channel = cfg.get("channel")
        if channel is not None:
            channel = str(channel).strip() or None
        arguments = cfg.get("arguments")
        if isinstance(arguments, str):
            arguments = arguments.strip() or None
        else:
            arguments = None
        airmon = cfg.get("airmon")
        return {"channel": channel, "arguments": arguments, "airmon": airmon}

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

    def _summarize_with_llm(
        self,
        agg: Dict[str, Any],
        *,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        payload = ""
        truncated = False
        max_chars = self._llm_max_chars()
        try:
            payload_obj = context if isinstance(context, dict) else agg
            payload, truncated = prepare_json_payload(payload_obj, max_chars=max_chars)
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
            meta = {
                "call_type": "summary",
                "error": str(e),
            }
            if payload:
                meta["input_truncated"] = bool(truncated)
                meta["input_chars"] = len(payload)
                meta["max_input_chars"] = int(max_chars)
            return None, meta

    def _build_llm_summary_context(self, agg: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        def norm_sev(value: Any) -> str:
            s = str(value or "INFO").strip().upper()
            return s or "INFO"

        # Tool execution status (so the LLM knows what did/didn't run).
        tool_runs: List[Dict[str, Any]] = []
        for entry in agg.get("results", []) or []:
            if not isinstance(entry, dict):
                continue
            tool = str(entry.get("tool") or "").strip() or "unknown"
            skipped = bool(entry.get("skipped"))
            success = bool(entry.get("success")) if not skipped else False
            status = "skipped" if skipped else ("success" if success else "failed")
            run = {
                "tool": tool,
                "status": status,
            }
            cmd = entry.get("command")
            if isinstance(cmd, str) and cmd.strip():
                run["command"] = cmd.strip()
            err = entry.get("error") if not skipped else entry.get("reason")
            if isinstance(err, str) and err.strip():
                run["error"] = err.strip()
            phase = entry.get("phase")
            if isinstance(phase, str) and phase.strip():
                run["phase"] = phase.strip()
            tgt = entry.get("target")
            if isinstance(tgt, str) and tgt.strip():
                run["target"] = tgt.strip()
            tool_runs.append(run)

        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        counts = {k: 0 for k in sev_order}
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            sev = norm_sev(f.get("severity"))
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1

        # Dedupe + sort findings so important items survive truncation.
        def f_key(f: Dict[str, Any]) -> tuple:
            return (
                norm_sev(f.get("severity")),
                str(f.get("tool") or ""),
                str(f.get("title") or ""),
                str(f.get("evidence") or ""),
            )

        unique: List[Dict[str, Any]] = []
        seen = set()
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            k = f_key(f)
            if k in seen:
                continue
            seen.add(k)
            unique.append(f)

        unique.sort(
            key=lambda f: (
                -self._severity_rank(norm_sev(f.get("severity"))),
                str(f.get("tool") or ""),
                str(f.get("title") or ""),
            )
        )

        max_total = 60
        max_info = 15
        selected: List[Dict[str, Any]] = []
        info_count = 0
        for f in unique:
            sev = norm_sev(f.get("severity"))
            if sev == "INFO":
                if info_count >= max_info:
                    continue
                info_count += 1
            item = {
                "severity": sev,
                "title": str(f.get("title") or ""),
                "evidence": str(f.get("evidence") or ""),
                "tool": str(f.get("tool") or ""),
            }
            if f.get("type") is not None:
                item["type"] = f.get("type")
            if isinstance(f.get("recommendation"), str) and str(f.get("recommendation")).strip():
                item["recommendation"] = str(f.get("recommendation")).strip()
            selected.append(item)
            if len(selected) >= max_total:
                break

        run_type = agg.get("report_kind")
        if not isinstance(run_type, str) or not run_type.strip():
            run_type = "audit"

        ctx: Dict[str, Any] = {
            "run_type": str(run_type),
            "target": agg.get("target"),
            "scan_host": agg.get("scan_host"),
            "mode": agg.get("mode"),
            "open_ports": agg.get("open_ports"),
            "web_targets": agg.get("web_targets"),
            "tools": tool_runs,
            "findings_overview": counts,
            "findings": selected,
        }
        compliance_profile = agg.get("compliance_profile")
        if isinstance(compliance_profile, str) and compliance_profile.strip():
            ctx["compliance_profile"] = compliance_profile.strip()
            framework = agg.get("compliance_framework")
            if isinstance(framework, str) and framework.strip():
                ctx["compliance_framework"] = framework.strip()

        ai = agg.get("ai_audit")
        if isinstance(ai, dict):
            planner = ai.get("planner") if isinstance(ai.get("planner"), dict) else {}
            ctx["agentic_expansion"] = {
                "phase": ai.get("phase"),
                "notes": ai.get("notes"),
                "planner": planner.get("type"),
                "planner_error": planner.get("error"),
                "actions": [a.get("action") for a in (ai.get("actions") or []) if isinstance(a, dict)][:20],
            }
        return ctx

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
            # Medusa valid credentials (high risk)
            if tool == "medusa":
                for c in data.get("found_credentials", []) or []:
                    if not isinstance(c, dict):
                        continue
                    svc = (c.get("module") or data.get("module") or "").strip().lower() or "service"
                    host = (c.get("host") or data.get("target") or "").strip() or "host"
                    login = (c.get("login") or "").strip()
                    password = redact_secret(c.get("password"))
                    where = f"{svc}://{host}"
                    findings.append({
                        "severity": "HIGH",
                        "title": "Valid credentials discovered (bruteforce)",
                        "evidence": f"{where} login={login} password={password}".strip(),
                        "tool": "medusa",
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
            # ffuf paths (content discovery)
            if tool == "ffuf":
                for path in data.get("findings", []):
                    findings.append(
                        {
                            "severity": "INFO",
                            "title": "Discovered path",
                            "evidence": str(path),
                            "tool": "ffuf",
                        }
                    )
            # katana endpoints (crawl)
            if tool == "katana":
                for url in (data.get("urls") or data.get("findings") or [])[:200]:
                    findings.append(
                        {
                            "severity": "INFO",
                            "title": "Discovered endpoint",
                            "evidence": str(url),
                            "tool": "katana",
                        }
                    )
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
            # WPScan findings (WordPress-specific)
            if tool == "wpscan":
                scan_data = data.get("scan_data", {})
                if isinstance(scan_data, dict):
                    for vuln in scan_data.get("vulnerabilities", []) or []:
                        if not isinstance(vuln, dict):
                            continue
                        title = str(vuln.get("title") or "WordPress vulnerability").strip()
                        component = str(vuln.get("component") or "").strip()
                        fixed_in = str(vuln.get("fixed_in") or "").strip()
                        details = []
                        if component:
                            details.append(f"component={component}")
                        if fixed_in:
                            details.append(f"fixed_in={fixed_in}")
                        evidence = title
                        if details:
                            evidence = f"{title} ({', '.join(details)})"
                        findings.append({
                            "severity": "MEDIUM",
                            "title": title,
                            "evidence": evidence,
                            "tool": "wpscan",
                            "type": vuln.get("type"),
                        })
                    for item in scan_data.get("interesting_findings", []) or []:
                        if isinstance(item, dict):
                            text = item.get("to_s") or item.get("type") or item.get("url")
                            if not isinstance(text, str) or not text.strip():
                                text = str(item)
                        else:
                            text = str(item)
                        text = text.strip()
                        if not text:
                            continue
                        findings.append({
                            "severity": "INFO",
                            "title": "WordPress interesting finding",
                            "evidence": text,
                            "tool": "wpscan",
                        })
                    for user in scan_data.get("users", []) or []:
                        if not isinstance(user, dict):
                            continue
                        username = str(user.get("username") or "").strip()
                        if not username:
                            continue
                        details = []
                        if user.get("id") is not None:
                            details.append(f"id={user.get('id')}")
                        slug = str(user.get("slug") or "").strip()
                        if slug:
                            details.append(f"slug={slug}")
                        evidence = f"username={username}"
                        if details:
                            evidence = f"{evidence} ({', '.join(details)})"
                        findings.append({
                            "severity": "INFO",
                            "title": "WordPress user enumerated",
                            "evidence": evidence,
                            "tool": "wpscan",
                        })
            # Searchsploit (offline exploit references)
            if tool == "searchsploit":
                for f in data.get("findings", []) or []:
                    if not isinstance(f, dict):
                        continue
                    title = str(f.get("title") or "").strip()
                    path = str(f.get("path") or "").strip()
                    kind = str(f.get("kind") or "").strip()
                    if not title and not path:
                        continue
                    evidence = title
                    if path:
                        evidence = f"{evidence} ({path})" if evidence else path
                    findings.append(
                        {
                            "severity": "INFO",
                            "title": "Potential exploit reference",
                            "evidence": evidence,
                            "tool": "searchsploit",
                            "type": kind or None,
                        }
                    )
            # CrackMapExec/NetExec findings
            if tool == "crackmapexec":
                scan_data = data.get("scan_data", {})
                if isinstance(scan_data, dict):
                    for cred in (scan_data.get("credentials") or [])[:50]:
                        if not isinstance(cred, dict):
                            continue
                        host = cred.get("host") or cred.get("ip") or ""
                        login = cred.get("username") or cred.get("user") or ""
                        password = redact_secret(cred.get("password"))
                        domain = cred.get("domain") or ""
                        evidence_parts = []
                        if host:
                            evidence_parts.append(f"host={host}")
                        if domain:
                            evidence_parts.append(f"domain={domain}")
                        if login:
                            evidence_parts.append(f"login={login}")
                        evidence_parts.append(f"password={password}")
                        findings.append({
                            "severity": "HIGH",
                            "title": "Valid credentials discovered (CME/NetExec)",
                            "evidence": ", ".join(evidence_parts).strip(),
                            "tool": "crackmapexec",
                        })
                    for finding in (scan_data.get("findings") or [])[:50]:
                        if not isinstance(finding, dict):
                            continue
                        msg = str(finding.get("message") or "").strip()
                        if not msg:
                            msg = str(finding)
                        findings.append({
                            "severity": "HIGH",
                            "title": "Privilege escalation indicator",
                            "evidence": msg,
                            "tool": "crackmapexec",
                        })
                    for share in (scan_data.get("shares") or [])[:50]:
                        if not isinstance(share, dict):
                            continue
                        name = str(share.get("name") or "").strip()
                        perms = str(share.get("permissions") or "").strip()
                        host = str(share.get("host") or "").strip()
                        remark = str(share.get("remark") or "").strip()
                        parts = []
                        if name:
                            parts.append(f"share={name}")
                        if perms:
                            parts.append(f"perms={perms}")
                        if host:
                            parts.append(f"host={host}")
                        if remark:
                            parts.append(f"remark={remark}")
                        findings.append({
                            "severity": "INFO",
                            "title": "SMB share discovered",
                            "evidence": ", ".join(parts).strip(),
                            "tool": "crackmapexec",
                        })
            # ScoutSuite findings (multi-cloud)
            if tool == "scoutsuite":
                scan_data = data.get("scan_data", {})
                for item in (scan_data.get("findings") or [])[:200]:
                    if not isinstance(item, dict):
                        continue
                    severity = str(item.get("severity") or "INFO").upper()
                    title = str(item.get("title") or "ScoutSuite finding")
                    evidence = str(item.get("evidence") or "")
                    findings.append(
                        {
                            "severity": severity,
                            "title": title,
                            "evidence": evidence,
                            "tool": "scoutsuite",
                        }
                    )
            # Prowler findings (AWS)
            if tool == "prowler":
                scan_data = data.get("scan_data", {})
                for item in (scan_data.get("findings") or [])[:500]:
                    if not isinstance(item, dict):
                        continue
                    severity = str(item.get("severity") or "MEDIUM").upper()
                    title = str(item.get("title") or "Prowler finding")
                    evidence = str(item.get("evidence") or "")
                    findings.append(
                        {
                            "severity": severity,
                            "title": title,
                            "evidence": evidence,
                            "tool": "prowler",
                        }
                    )
            # subfinder subdomains
            if tool == "subfinder":
                for host in (data.get("hosts") or data.get("findings") or [])[:200]:
                    findings.append(
                        {
                            "severity": "INFO",
                            "title": "Discovered subdomain",
                            "evidence": str(host),
                            "tool": "subfinder",
                        }
                    )
            # theHarvester OSINT results
            if tool == "theharvester":
                scan_data = data.get("scan_data", {})
                if isinstance(scan_data, dict):
                    for email in (scan_data.get("emails") or [])[:50]:
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "OSINT email discovered",
                                "evidence": str(email),
                                "tool": "theharvester",
                            }
                        )
                    for host in (scan_data.get("hosts") or [])[:50]:
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "OSINT host discovered",
                                "evidence": str(host),
                                "tool": "theharvester",
                            }
                        )
                    for ip in (scan_data.get("ips") or [])[:50]:
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "OSINT IP discovered",
                                "evidence": str(ip),
                                "tool": "theharvester",
                            }
                        )
                    for url in (scan_data.get("interesting_urls") or [])[:50]:
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "OSINT URL discovered",
                                "evidence": str(url),
                                "tool": "theharvester",
                            }
                        )
                    for asn in (scan_data.get("asns") or [])[:50]:
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "OSINT ASN discovered",
                                "evidence": str(asn),
                                "tool": "theharvester",
                            }
                        )
            # netdiscover LAN hosts
            if tool == "netdiscover":
                scan_data = data.get("scan_data", {})
                if isinstance(scan_data, dict):
                    for host in (scan_data.get("hosts") or [])[:50]:
                        if not isinstance(host, dict):
                            continue
                        ip_addr = str(host.get("ip") or "").strip()
                        mac = str(host.get("mac") or "").strip()
                        vendor = str(host.get("vendor") or "").strip()
                        evidence_parts = []
                        if ip_addr:
                            evidence_parts.append(f"ip={ip_addr}")
                        if mac:
                            evidence_parts.append(f"mac={mac}")
                        if vendor:
                            evidence_parts.append(f"vendor={vendor}")
                        evidence = ", ".join(evidence_parts) if evidence_parts else str(host)
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "Discovered LAN host",
                                "evidence": evidence,
                                "tool": "netdiscover",
                            }
                        )
            # Aircrack-ng WiFi findings (open/WEP networks)
            if tool == "aircrack-ng":
                scan_data = data.get("scan_data", {})
                if isinstance(scan_data, dict):
                    for ap in (scan_data.get("access_points") or [])[:100]:
                        if not isinstance(ap, dict):
                            continue
                        security = str(ap.get("security") or "").upper()
                        privacy = str(ap.get("privacy") or "").upper()
                        is_open = security == "OPEN" or ("WPA" not in privacy and "WEP" not in privacy)
                        is_wep = security == "WEP" or "WEP" in privacy
                        if not (is_open or is_wep):
                            continue
                        bssid = str(ap.get("bssid") or "").strip()
                        essid = str(ap.get("essid") or "").strip()
                        channel = ap.get("channel")
                        evidence_parts = []
                        if essid:
                            evidence_parts.append(f"essid={essid}")
                        if bssid:
                            evidence_parts.append(f"bssid={bssid}")
                        if channel is not None:
                            evidence_parts.append(f"channel={channel}")
                        if privacy:
                            evidence_parts.append(f"privacy={privacy}")
                        severity = "HIGH" if is_wep else "MEDIUM"
                        title = "WEP network detected" if is_wep else "Open WiFi network detected"
                        findings.append(
                            {
                                "severity": severity,
                                "title": title,
                                "evidence": ", ".join(evidence_parts).strip(),
                                "tool": "aircrack-ng",
                            }
                        )
            # Supabase security audit (URLs/keys/RPC exposure)
            if tool == "supabase_audit":
                for item in data.get("exposed_urls", []) or []:
                    if not isinstance(item, dict):
                        continue
                    supabase_url = str(item.get("supabase_url") or "").strip()
                    source = str(item.get("source") or "").strip()
                    evidence = supabase_url
                    if source:
                        evidence = f"{supabase_url} (source={source})"
                    if evidence.strip():
                        findings.append(
                            {
                                "severity": "INFO",
                                "title": "Supabase project URL exposed in client content",
                                "evidence": evidence.strip(),
                                "tool": "supabase_audit",
                            }
                        )
                for key in data.get("keys", []) or []:
                    if not isinstance(key, dict):
                        continue
                    key_type = str(key.get("type") or "unknown").lower()
                    masked = str(key.get("value") or "").strip()
                    source = str(key.get("source") or "").strip()
                    evidence_parts = []
                    if masked:
                        evidence_parts.append(f"key={masked}")
                    if source:
                        evidence_parts.append(f"source={source}")
                    evidence = ", ".join(evidence_parts)
                    if key_type == "service_role":
                        findings.append(
                            {
                                "severity": "CRITICAL",
                                "title": "Supabase service role key exposed",
                                "evidence": evidence or "Service role key detected in client content",
                                "recommendation": "Rotate the service role key immediately and remove it from client-side code.",
                                "tool": "supabase_audit",
                            }
                        )
                    elif key_type == "anon":
                        findings.append(
                            {
                                "severity": "LOW",
                                "title": "Supabase anon key exposed in client content",
                                "evidence": evidence or "Anon key detected in client content",
                                "recommendation": "Verify RLS policies and limit anon key usage to least privilege.",
                                "tool": "supabase_audit",
                            }
                        )
                    else:
                        findings.append(
                            {
                                "severity": "MEDIUM",
                                "title": "Potential Supabase API key exposed",
                                "evidence": evidence or "Potential key detected in client content",
                                "recommendation": "Validate the key type and rotate if sensitive.",
                                "tool": "supabase_audit",
                            }
                        )
                for exposure in data.get("exposures", []) or []:
                    if not isinstance(exposure, dict):
                        continue
                    exp_type = str(exposure.get("type") or "").strip()
                    url = str(exposure.get("url") or "").strip()
                    status = exposure.get("status")
                    evidence = url
                    if status is not None:
                        evidence = f"{url} (HTTP {status})"
                    if exp_type == "rest_api_public":
                        findings.append(
                            {
                                "severity": "HIGH",
                                "title": "Supabase REST API accessible without authentication",
                                "evidence": evidence,
                                "recommendation": "Enforce RLS and require API keys/auth for REST endpoints.",
                                "tool": "supabase_audit",
                            }
                        )
                    elif exp_type == "rpc_root_public":
                        findings.append(
                            {
                                "severity": "MEDIUM",
                                "title": "Supabase RPC endpoint exposed without authentication",
                                "evidence": evidence,
                                "recommendation": "Restrict RPC access with policies and authentication.",
                                "tool": "supabase_audit",
                            }
                        )
                    elif exp_type == "rpc_public":
                        rpc_name = str(exposure.get("rpc") or "").strip()
                        title = "Supabase RPC callable without authentication"
                        if rpc_name:
                            title = f"Supabase RPC '{rpc_name}' callable without authentication"
                        findings.append(
                            {
                                "severity": "HIGH",
                                "title": title,
                                "evidence": evidence,
                                "recommendation": "Require authentication for RPCs and enforce RLS or role checks.",
                                "tool": "supabase_audit",
                            }
                        )
                    elif exp_type == "rls_misconfig":
                        findings.append(
                            {
                                "severity": "HIGH",
                                "title": "Supabase RLS may be disabled",
                                "evidence": evidence,
                                "recommendation": "Enable RLS and verify policies for affected tables/views.",
                                "tool": "supabase_audit",
                            }
                        )
        return findings

    def _apply_compliance_tags(
        self,
        agg: Dict[str, Any],
        findings: List[Dict[str, Any]],
        compliance_profile: Optional[str],
    ) -> List[Dict[str, Any]]:
        profile = self._normalize_compliance_profile(compliance_profile) or self._normalize_compliance_profile(
            agg.get("compliance_profile")
        )
        if not profile:
            return findings
        if profile not in COMPLIANCE_PROFILES:
            return findings

        def reference_for(control_key: str) -> Optional[str]:
            ref = COMPLIANCE_CONTROL_REFERENCES.get(control_key, {}).get(profile)
            if not ref:
                return None
            return str(ref)

        def add_mapping(finding: Dict[str, Any], control_key: str, confidence: str) -> None:
            ref = reference_for(control_key)
            if not ref:
                return
            confidence_norm = str(confidence or "medium").strip().lower()
            if confidence_norm not in ("low", "medium", "high"):
                confidence_norm = "medium"
            mapping = {
                "status": "potential_gap",
                "control_key": control_key,
                "reference": ref,
                "confidence": confidence_norm,
            }
            mappings = finding.get("compliance_mappings")
            if not isinstance(mappings, list):
                mappings = []
                finding["compliance_mappings"] = mappings
            if mapping not in mappings:
                mappings.append(mapping)

            # Backward-compatible text tags for older report renderers.
            text_tag = f"Potential Gap: {ref} (mapping confidence: {confidence_norm})"
            tags = finding.get("compliance_tags")
            if not isinstance(tags, list):
                tags = []
                finding["compliance_tags"] = tags
            if text_tag not in tags:
                tags.append(text_tag)

        def has_any(text: str, phrases: Sequence[str]) -> bool:
            for phrase in phrases:
                if phrase in text:
                    return True
            return False

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            tool = str(finding.get("tool") or "").lower()
            title = str(finding.get("title") or "").strip().lower()
            severity = str(finding.get("severity") or "INFO").strip().upper()

            if tool == "sslscan":
                if has_any(
                    title,
                    (
                        "weak tls",
                        "weak cipher",
                        "tlsv1",
                        "tls 1.0",
                        "tls 1.1",
                        "self-signed",
                        "certificate",
                        "insecure protocol",
                        "expired",
                    ),
                ):
                    add_mapping(finding, "crypto", "high")
                elif severity in ("HIGH", "CRITICAL", "MEDIUM"):
                    add_mapping(finding, "crypto", "medium")

            if tool == "sqlmap" or "sql injection" in title:
                add_mapping(finding, "vuln_mgmt", "high")

            if tool in ("hydra", "medusa") or has_any(
                title, ("valid credentials", "weak password", "default credentials", "bruteforce")
            ):
                add_mapping(finding, "access_control", "high")

            if tool in ("nuclei", "nikto", "ffuf", "gobuster"):
                # Avoid broad false mapping on generic informational records (for example CAA).
                if "caa record" in title:
                    pass
                elif has_any(
                    title,
                    (
                        "unauthenticated",
                        "default credentials",
                        "directory listing",
                        "prometheus metrics",
                        "open redirect",
                        "xss",
                        "sqli",
                        "cve-",
                        "admin panel",
                        "exposed",
                        "authentication bypass",
                        "missing security headers",
                        "allowed options method",
                    ),
                ):
                    conf = "medium" if severity in ("INFO", "LOW") else "high"
                    add_mapping(finding, "vuln_mgmt", conf)
                elif severity in ("HIGH", "CRITICAL", "MEDIUM"):
                    add_mapping(finding, "vuln_mgmt", "medium")

            if tool == "trivy" and severity in ("HIGH", "CRITICAL", "MEDIUM"):
                add_mapping(finding, "vuln_mgmt", "high")

            if tool == "supabase_audit":
                if has_any(title, ("service role key", "without authentication", "rest api accessible", "rpc", "rls")):
                    add_mapping(finding, "access_control", "high")
                if has_any(title, ("service role key", "anon key", "rls", "rpc", "rest api accessible")):
                    conf = "high" if "service role key" in title else "medium"
                    add_mapping(finding, "data_protection", conf)

        return findings

    def _nmap_args_for_mode(self, mode: str, compliance_profile: Optional[str] = None) -> str:
        normalized = self._normalize_compliance_profile(compliance_profile)
        if normalized and normalized.startswith("compliance_"):
            return "-sV --script ssl-enum-ciphers -p-"
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
        compliance_profile: Optional[str] = None,
        nuclei_rate_limit: int = 0,
        nuclei_tags: Optional[str] = None,
        nuclei_severity: Optional[str] = None,
        nuclei_templates: Optional[str] = None,
        web_targets_override: Optional[Sequence[str]] = None,
        gobuster_threads: int = 10,
        gobuster_wordlist: Optional[str] = None,
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
        normalized_compliance = self._normalize_compliance_profile(compliance_profile)
        compliance_label = self._compliance_profile_label(normalized_compliance)
        compliance_focus = None
        if normalized_compliance:
            profile_spec = COMPLIANCE_PROFILES.get(normalized_compliance)
            if isinstance(profile_spec, dict):
                compliance_focus = profile_spec.get("focus")

        cfg_obj = None
        try:
            cfg_obj = getattr(self.llm, "config", None)
            cfg_obj = getattr(cfg_obj, "config", None) if cfg_obj is not None else None
        except Exception:
            cfg_obj = None
        cfg_dict = cfg_obj if isinstance(cfg_obj, dict) else {}

        if int(nuclei_rate_limit or 0) <= 0:
            cfg_rate = self._tool_config("nuclei").get("rate_limit")
            try:
                cfg_rate_int = int(cfg_rate)
            except Exception:
                cfg_rate_int = 0
            if cfg_rate_int > 0:
                nuclei_rate_limit = cfg_rate_int

        if not nuclei_tags:
            cfg_tags = self._tool_config("nuclei").get("tags")
            if isinstance(cfg_tags, str) and cfg_tags.strip():
                nuclei_tags = cfg_tags.strip()
        if not nuclei_severity:
            cfg_sev = self._tool_config("nuclei").get("severity")
            if isinstance(cfg_sev, str) and cfg_sev.strip():
                nuclei_severity = cfg_sev.strip()
        if not nuclei_templates:
            cfg_templates = self._tool_config("nuclei").get("templates")
            if isinstance(cfg_templates, str) and cfg_templates.strip():
                nuclei_templates = cfg_templates.strip()

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
                "nuclei_templates": nuclei_templates,
                "gobuster_threads": gobuster_threads,
                "gobuster_wordlist": gobuster_wordlist,
                "nikto_enabled": bool(run_nikto),
                "hydra_enabled": bool(run_hydra),
                "hydra_services": hydra_services,
                "hydra_threads": int(hydra_threads),
                "theharvester_enabled": bool(run_theharvester),
                "theharvester_sources": theharvester_sources,
                "theharvester_limit": theharvester_limit,
                "theharvester_start": theharvester_start,
                "netdiscover_enabled": bool(run_netdiscover),
                "netdiscover_range": netdiscover_range,
                "netdiscover_interface": netdiscover_interface,
                "netdiscover_passive": bool(netdiscover_passive),
                "netdiscover_fast": bool(netdiscover_fast),
                "aircrack_enabled": bool(run_aircrack),
                "aircrack_interface": aircrack_interface,
                "aircrack_channel": aircrack_channel,
                "aircrack_args": aircrack_args,
                "aircrack_airmon": bool(aircrack_airmon),
                "medusa_enabled": bool(run_medusa),
                "medusa_module": medusa_module,
                "medusa_port": medusa_port,
                "medusa_threads": int(medusa_threads),
                "crackmapexec_enabled": bool(run_crackmapexec),
                "cme_protocol": cme_protocol,
                "cme_module": cme_module,
                "scoutsuite_enabled": bool(run_scoutsuite),
                "scoutsuite_provider": scoutsuite_provider,
                "prowler_enabled": bool(run_prowler),
                "compliance_profile": normalized_compliance,
            },
            "safety": {"aggressive_caps": caps_meta},
        }
        if normalized_compliance:
            agg["compliance_profile"] = normalized_compliance
            if compliance_label:
                agg["compliance_framework"] = compliance_label
            if isinstance(compliance_focus, str) and compliance_focus.strip():
                agg["compliance_focus"] = compliance_focus.strip()
        if container_image:
            agg["container_image"] = container_image
        report_root = Path(output).parent if output is not None else Path("reports")
        try:
            report_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

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
                    arguments=self._nmap_args_for_mode(mode, compliance_profile=normalized_compliance),
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

        def run_searchsploit_from_nmap(nmap_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
            """
            Best-effort offline exploit reference lookup for detected services.
            Kept INFO-only and bounded to avoid noisy/slow behavior.
            """
            if not self._has_scanner("searchsploit"):
                return [self._skip_tool("searchsploit", "Scanner not available")]
            if not self._tool_enabled("searchsploit", default=False):
                return [self._skip_disabled("searchsploit")]
            if not nmap_entry or not nmap_entry.get("success"):
                return [self._skip_tool("searchsploit", "No nmap results to derive service fingerprints")]

            data = nmap_entry.get("data") if isinstance(nmap_entry.get("data"), dict) else {}
            scan_data = data.get("scan_data", {}) if isinstance(data, dict) else {}

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
                return [self._skip_tool("searchsploit", "No version/service fingerprints available")]

            results: List[Dict[str, Any]] = []
            for q in queries[:5]:
                note("tool_start", "searchsploit", f"Running searchsploit for: {q}")
                results.append(
                    self._run_tool(
                        "searchsploit",
                        lambda q=q: self.scanners["searchsploit"].search(
                            q,
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("searchsploit"),
                        ),
                    )
                )
                note("tool_end", "searchsploit", f"Finished searchsploit for: {q}")
                if canceled():
                    break
            return results

        def run_subfinder(domain_target: str) -> Dict[str, Any]:
            if not self._has_scanner("subfinder"):
                return self._skip_tool("subfinder", "Scanner not available")
            if not self._tool_enabled("subfinder", default=False):
                return self._skip_disabled("subfinder")
            if not self._should_run_dnsenum(domain_target):
                return self._skip_tool("subfinder", self._dns_target_skip_reason(domain_target))
            note("tool_start", "subfinder", "Running subfinder")
            entry = self._run_tool(
                "subfinder",
                lambda: self.scanners["subfinder"].scan(
                    domain_target,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("subfinder"),
                ),
            )
            note("tool_end", "subfinder", "Finished subfinder")
            return entry

        theharvester_cfg = self._theharvester_args()

        def resolve_theharvester_settings() -> Dict[str, Any]:
            sources = theharvester_sources if theharvester_sources is not None else theharvester_cfg.get("sources")
            if isinstance(sources, str):
                sources = sources.strip() or None
            else:
                sources = None

            limit = theharvester_limit if theharvester_limit is not None else theharvester_cfg.get("limit")
            try:
                limit = int(limit)
            except Exception:
                limit = 500
            if limit <= 0:
                limit = 500

            start = theharvester_start if theharvester_start is not None else theharvester_cfg.get("start")
            try:
                start = int(start)
            except Exception:
                start = 0
            if start < 0:
                start = 0

            arguments = theharvester_args if theharvester_args is not None else theharvester_cfg.get("arguments")
            if isinstance(arguments, str):
                arguments = arguments.strip() or None
            else:
                arguments = None

            return {"sources": sources, "limit": limit, "start": start, "arguments": arguments}

        def run_theharvester_if_requested(domain_target: str) -> Optional[Dict[str, Any]]:
            if not run_theharvester:
                return None
            if not self._has_scanner("theharvester"):
                return self._skip_tool("theharvester", "Scanner not available")
            if not self._should_run_dnsenum(domain_target):
                return self._skip_tool("theharvester", self._dns_target_skip_reason(domain_target))

            settings = resolve_theharvester_settings()
            note("tool_start", "theharvester", "Running theHarvester (OSINT)")
            entry = self._run_tool_if_enabled(
                "theharvester",
                lambda: self.scanners["theharvester"].scan(
                    domain_target,
                    sources=settings["sources"],
                    limit=settings["limit"],
                    start=settings["start"],
                    arguments=settings["arguments"],
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("theharvester"),
                ),
            )
            note("tool_end", "theharvester", "Finished theHarvester")
            return entry

        def run_netdiscover_if_requested() -> Optional[Dict[str, Any]]:
            if not run_netdiscover:
                return None
            if not self._has_scanner("netdiscover"):
                return self._skip_tool("netdiscover", "Scanner not available")
            if not netdiscover_range and not netdiscover_passive:
                return self._skip_tool("netdiscover", "Provide --netdiscover-range or --netdiscover-passive")
            if netdiscover_range:
                try:
                    net = ipaddress.ip_network(str(netdiscover_range), strict=False)
                    if not net.is_private:
                        return self._skip_tool("netdiscover", "Netdiscover supports private LAN ranges only")
                except Exception:
                    return self._skip_tool("netdiscover", "Invalid --netdiscover-range CIDR")

            note("tool_start", "netdiscover", "Running netdiscover (LAN discovery)")
            entry = self._run_tool_if_enabled(
                "netdiscover",
                lambda: self.scanners["netdiscover"].scan(
                    interface=netdiscover_interface,
                    range=netdiscover_range,
                    passive=bool(netdiscover_passive),
                    fast_mode=bool(netdiscover_fast),
                    arguments=netdiscover_args,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("netdiscover"),
                ),
            )
            note("tool_end", "netdiscover", "Finished netdiscover")
            return entry

        aircrack_cfg = self._aircrack_args()

        def run_aircrack_if_requested() -> Optional[Dict[str, Any]]:
            if not run_aircrack:
                return None
            if not aircrack_interface:
                return self._skip_tool("aircrack-ng", "Provide --aircrack-interface")
            if not self._has_scanner("aircrack-ng"):
                return self._skip_tool("aircrack-ng", "Scanner not available")

            channel = aircrack_channel if aircrack_channel is not None else aircrack_cfg.get("channel")
            if channel is not None:
                channel = str(channel).strip() or None
            args = aircrack_args if aircrack_args is not None else aircrack_cfg.get("arguments")
            airmon = bool(aircrack_airmon) or bool(aircrack_cfg.get("airmon"))

            ts = time.strftime("%Y%m%d-%H%M%S")
            output_dir = report_root / f"aircrack-{ts}"
            note("tool_start", "aircrack-ng", "Running airodump-ng (WiFi capture)")
            entry = self._run_tool(
                "aircrack-ng",
                lambda: self.scanners["aircrack-ng"].scan(
                    interface=aircrack_interface,
                    channel=channel,
                    output_dir=str(output_dir),
                    arguments=args,
                    airmon=airmon,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("aircrack-ng"),
                ),
            )
            note("tool_end", "aircrack-ng", "Finished airodump-ng")
            return entry

        def run_medusa_from_nmap(nmap_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
            if not run_medusa:
                return []
            if not medusa_usernames or not medusa_passwords:
                return [self._skip_tool("medusa", "Missing --medusa-usernames/--medusa-passwords")]
            if not self._has_scanner("medusa"):
                return [self._skip_tool("medusa", "Scanner not available")]
            if not nmap_entry or not nmap_entry.get("success"):
                return [self._skip_tool("medusa", "No nmap results to derive services/ports")]

            scan_data = nmap_entry.get("data", {}).get("scan_data", {})
            ports: List[Dict[str, Any]] = []
            for host in (scan_data or {}).get("hosts", []) or []:
                for p in host.get("ports", []) or []:
                    try:
                        if str(p.get("state", "")).lower() != "open":
                            continue
                        ports.append(p)
                    except Exception:
                        continue

            service_map = {
                "ssh": "ssh",
                "ftp": "ftp",
                "telnet": "telnet",
                "smtp": "smtp",
                "pop3": "pop3",
                "imap": "imap",
                "imaps": "imap",
                "mysql": "mysql",
                "postgres": "postgres",
                "postgresql": "postgres",
                "mssql": "mssql",
                "ms-sql-s": "mssql",
                "rdp": "rdp",
                "ms-wbt-server": "rdp",
                "microsoft-ds": "smbnt",
                "netbios-ssn": "smbnt",
                "smb": "smbnt",
            }
            port_map = {
                22: "ssh",
                21: "ftp",
                23: "telnet",
                25: "smtp",
                110: "pop3",
                143: "imap",
                139: "smbnt",
                445: "smbnt",
                3389: "rdp",
                3306: "mysql",
                5432: "postgres",
                1433: "mssql",
            }

            module_ports: Dict[str, List[int]] = {}
            for p in ports:
                try:
                    port = int(p.get("port"))
                except Exception:
                    continue
                svc = str(p.get("service") or "").lower()
                module = service_map.get(svc) or port_map.get(port)
                if not module:
                    continue
                module_ports.setdefault(module, []).append(port)

            results: List[Dict[str, Any]] = []
            module_override = (medusa_module or "").strip().lower()
            if module_override:
                ports_for_module = []
                if medusa_port:
                    ports_for_module = [int(medusa_port)]
                else:
                    ports_for_module = sorted(set(module_ports.get(module_override, [])))
                if not ports_for_module:
                    return [self._skip_tool("medusa", f"No {module_override} service detected by nmap")]
                module_ports = {module_override: ports_for_module}
            elif not module_ports:
                return [self._skip_tool("medusa", "No supported services detected by nmap")]

            for module, ports_list in module_ports.items():
                for port in sorted(set(ports_list))[:2]:
                    note("tool_start", "medusa", f"Running medusa ({module}) on port {port}")
                    results.append(
                        self._run_tool(
                            "medusa",
                            lambda module=module, port=port: self.scanners["medusa"].run(
                                scan_host,
                                module,
                                medusa_usernames,
                                medusa_passwords,
                                port=port,
                                threads=int(medusa_threads),
                                timeout_per_connection=int(medusa_timeout),
                                options=medusa_options,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("medusa"),
                            ),
                        )
                    )
                    note("tool_end", "medusa", f"Finished medusa ({module}) on port {port}")
                    if canceled():
                        return results
            return results

        def run_crackmapexec_from_nmap(nmap_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
            if not run_crackmapexec:
                return []
            if not self._has_scanner("crackmapexec"):
                return [self._skip_tool("crackmapexec", "Scanner not available")]
            if not nmap_entry or not nmap_entry.get("success"):
                return [self._skip_tool("crackmapexec", "No nmap results to validate services")]

            if not (cme_username or cme_password or cme_hashes or cme_args):
                return [self._skip_tool("crackmapexec", "Provide creds/hashes or --cme-args for anonymous runs")]

            protocol = str(cme_protocol or "smb").strip().lower()
            open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {}))
            if protocol == "smb" and not any(p in (139, 445) for p in open_ports):
                return [self._skip_tool("crackmapexec", "No SMB ports detected (139/445)")]
            if protocol == "rdp" and 3389 not in open_ports:
                return [self._skip_tool("crackmapexec", "No RDP port detected (3389)")]
            if protocol == "ssh" and 22 not in open_ports:
                return [self._skip_tool("crackmapexec", "No SSH port detected (22)")]
            if protocol == "ldap" and not any(p in (389, 636) for p in open_ports):
                return [self._skip_tool("crackmapexec", "No LDAP ports detected (389/636)")]
            if protocol == "winrm" and not any(p in (5985, 5986) for p in open_ports):
                return [self._skip_tool("crackmapexec", "No WinRM ports detected (5985/5986)")]
            if protocol == "mssql" and 1433 not in open_ports:
                return [self._skip_tool("crackmapexec", "No MSSQL port detected (1433)")]

            enum_opts: List[str] = []
            if isinstance(cme_enum, str):
                for token in cme_enum.replace(";", ",").split(","):
                    t = token.strip()
                    if not t:
                        continue
                    enum_opts.append(t if t.startswith("-") else f"--{t}")

            note("tool_start", "crackmapexec", f"Running crackmapexec ({protocol})")
            entry = self._run_tool(
                "crackmapexec",
                lambda: self.scanners["crackmapexec"].scan(
                    scan_host,
                    protocol=protocol,
                    username=cme_username,
                    password=cme_password,
                    domain=cme_domain,
                    hashes=cme_hashes,
                    module=cme_module,
                    module_options=cme_module_options,
                    enumerate_options=enum_opts or None,
                    arguments=cme_args,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("crackmapexec"),
                ),
            )
            note("tool_end", "crackmapexec", "Finished crackmapexec")
            return [entry]

        scoutsuite_cfg = self._scoutsuite_args()
        prowler_cfg = self._prowler_args()

        def run_scoutsuite_if_requested() -> Optional[Dict[str, Any]]:
            if not run_scoutsuite:
                return None
            if not self._has_scanner("scoutsuite"):
                return self._skip_tool("scoutsuite", "Scanner not available")
            provider = scoutsuite_provider or scoutsuite_cfg.get("provider") or "aws"
            provider = str(provider).strip().lower()
            if provider not in ("aws", "azure", "gcp"):
                return self._skip_tool("scoutsuite", f"Unsupported provider: {provider}")
            args = scoutsuite_args if scoutsuite_args is not None else scoutsuite_cfg.get("arguments")
            ts = time.strftime("%Y%m%d-%H%M%S")
            report_dir = report_root / f"scoutsuite-{ts}"
            note("tool_start", "scoutsuite", f"Running ScoutSuite ({provider})")
            entry = self._run_tool(
                "scoutsuite",
                lambda: self.scanners["scoutsuite"].scan(
                    provider=provider,
                    report_dir=str(report_dir),
                    arguments=args,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("scoutsuite"),
                ),
            )
            note("tool_end", "scoutsuite", "Finished ScoutSuite")
            return entry

        def run_prowler_if_requested() -> Optional[Dict[str, Any]]:
            if not run_prowler:
                return None
            if not self._has_scanner("prowler"):
                return self._skip_tool("prowler", "Scanner not available")
            args = prowler_args if prowler_args is not None else prowler_cfg.get("arguments")
            ts = time.strftime("%Y%m%d-%H%M%S")
            output_dir = report_root / f"prowler-{ts}"
            note("tool_start", "prowler", "Running Prowler (AWS)")
            entry = self._run_tool(
                "prowler",
                lambda: self.scanners["prowler"].scan(
                    output_dir=str(output_dir),
                    arguments=args,
                    cancel_event=cancel_event,
                    timeout_seconds=self._tool_timeout_seconds("prowler"),
                ),
            )
            note("tool_end", "prowler", "Finished Prowler")
            return entry

        def run_web_tools(web_target: str) -> List[Dict[str, Any]]:
            def tag(entry: Dict[str, Any]) -> Dict[str, Any]:
                if isinstance(entry, dict):
                    entry.setdefault("target", web_target)
                return entry

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
                results.append(tag(whatweb_entry))
                if canceled() or (isinstance(whatweb_entry.get("data"), dict) and whatweb_entry["data"].get("canceled")):
                    return results

                if self._has_scanner("wpscan"):
                    if self._whatweb_detects_wordpress(whatweb_entry):
                        wpscan_args = self._wpscan_args()
                        note("tool_start", "wpscan", "Running wpscan (WordPress detected)")
                        wpscan_entry = self._run_tool_if_enabled(
                            "wpscan",
                            lambda: self.scanners["wpscan"].scan(
                                web_target,
                                api_token=wpscan_args.get("api_token"),
                                enumerate=wpscan_args.get("enumerate"),
                                arguments=wpscan_args.get("arguments"),
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("wpscan"),
                            ),
                        )
                        note("tool_end", "wpscan", "Finished wpscan")
                    else:
                        wpscan_entry = self._skip_tool("wpscan", "WordPress not detected by whatweb")
                else:
                    wpscan_entry = self._skip_tool("wpscan", "Scanner not available")
                results.append(tag(wpscan_entry))
                if canceled() or (isinstance(wpscan_entry.get("data"), dict) and wpscan_entry["data"].get("canceled")):
                    return results

                note("tool_start", "nuclei", "Running nuclei")
                nuclei_entry = self._run_tool_if_enabled(
                    "nuclei",
                    lambda: self.scanners["nuclei"].scan(
                        web_target,
                        templates=nuclei_templates,
                        rate_limit=nuclei_rate_limit or None,
                        tags=nuclei_tags,
                        severity=nuclei_severity,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("nuclei"),
                    ),
                )
                note("tool_end", "nuclei", "Finished nuclei")
                results.append(tag(nuclei_entry))
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
                results.append(tag(gobuster_entry))

                # Optional fallback: ffuf (-ac) can handle wildcard/soft-404 responses
                # where gobuster refuses to continue.
                if (
                    not gobuster_entry.get("success")
                    and self._has_scanner("ffuf")
                    and self._tool_enabled("ffuf", default=False)
                ):
                    note("tool_start", "ffuf", "Running ffuf (fallback for content discovery)")
                    ffuf_entry = self._run_tool(
                        "ffuf",
                        lambda: self.scanners["ffuf"].scan(
                            web_target,
                            wordlist=gobuster_wordlist,
                            threads=max(10, int(gobuster_threads)),
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("ffuf"),
                        ),
                    )
                    ffuf_entry["fallback_for"] = "gobuster"
                    ffuf_entry["reason"] = "Fallback after gobuster failure"
                    note("tool_end", "ffuf", "Finished ffuf")
                    results.append(tag(ffuf_entry))

                if self._has_scanner("katana"):
                    note("tool_start", "katana", "Running katana (crawl)")
                    katana_entry = self._run_tool_if_enabled(
                        "katana",
                        lambda: self.scanners["katana"].crawl(
                            web_target,
                            depth=int(self._tool_config("katana").get("depth", 3) or 3),
                            concurrency=int(self._tool_config("katana").get("concurrency", 10) or 10),
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("katana"),
                        ),
                    )
                    results.append(tag(katana_entry))
                    note("tool_end", "katana", "Finished katana")
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
                    results.append(tag(self._skip_disabled("whatweb")))
                note("tool_start", "nuclei", "Running nuclei")
                if self._tool_enabled("nuclei", default=True):
                    futures[
                        ex.submit(
                            self._run_tool,
                            "nuclei",
                            lambda: self.scanners["nuclei"].scan(
                                web_target,
                                rate_limit=nuclei_rate_limit or None,
                                tags=nuclei_tags,
                                severity=nuclei_severity,
                                cancel_event=cancel_event,
                                timeout_seconds=self._tool_timeout_seconds("nuclei"),
                            ),
                        )
                    ] = "nuclei"
                else:
                    results.append(tag(self._skip_disabled("nuclei")))
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
                        results.append(tag(self._skip_disabled("gobuster")))
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
                        results.append(tag(self._skip_disabled("gobuster")))

                for fut in as_completed(futures):
                    tool = futures.get(fut, "tool")
                    try:
                        entry = fut.result()
                    except Exception as e:
                        entry = {"tool": tool, "success": False, "error": str(e)}
                    results.append(tag(entry))
                    note("tool_end", tool, f"Finished {tool}")
            whatweb_entry = None
            for entry in results:
                if isinstance(entry, dict) and entry.get("tool") == "whatweb":
                    whatweb_entry = entry
                    break
            if self._has_scanner("wpscan"):
                if self._whatweb_detects_wordpress(whatweb_entry):
                    wpscan_args = self._wpscan_args()
                    note("tool_start", "wpscan", "Running wpscan (WordPress detected)")
                    wpscan_entry = self._run_tool_if_enabled(
                        "wpscan",
                        lambda: self.scanners["wpscan"].scan(
                            web_target,
                            api_token=wpscan_args.get("api_token"),
                            enumerate=wpscan_args.get("enumerate"),
                            arguments=wpscan_args.get("arguments"),
                            cancel_event=cancel_event,
                            timeout_seconds=self._tool_timeout_seconds("wpscan"),
                        ),
                    )
                    note("tool_end", "wpscan", "Finished wpscan")
                else:
                    wpscan_entry = self._skip_tool("wpscan", "WordPress not detected by whatweb")
            else:
                wpscan_entry = self._skip_tool("wpscan", "Scanner not available")
            results.append(tag(wpscan_entry))
            return results

        # Recon & web scans (optional parallel overlap)
        nmap_entry: Optional[Dict[str, Any]] = None
        web_targets: List[str] = []
        lock_web_targets = False
        if web_targets_override:
            web_targets = [str(u).strip() for u in list(web_targets_override) if str(u).strip()]
            lock_web_targets = bool(web_targets)
        if not web_targets and normalized["base_url"]:
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
                for entry in run_searchsploit_from_nmap(nmap_entry):
                    agg["results"].append(entry)
                for entry in run_medusa_from_nmap(nmap_entry):
                    agg["results"].append(entry)
                for entry in run_crackmapexec_from_nmap(nmap_entry):
                    agg["results"].append(entry)

                # Optional domain expansion (does not block web tooling already started)
                if self._tool_enabled("subfinder", default=False) and self._has_scanner("subfinder") and self._should_run_dnsenum(scan_host):
                    agg["results"].append(run_subfinder(scan_host))

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
                    agg["results"].append(self._skip_tool("dnsenum", self._dns_target_skip_reason(scan_host)))

                harvester_entry = run_theharvester_if_requested(scan_host)
                if harvester_entry is not None:
                    agg["results"].append(harvester_entry)
                    if canceled() or (isinstance(harvester_entry.get("data"), dict) and harvester_entry["data"].get("canceled")):
                        agg["canceled"] = True
                        agg["finished_at"] = time.time()
                        return agg

                netdiscover_entry = run_netdiscover_if_requested()
                if netdiscover_entry is not None:
                    agg["results"].append(netdiscover_entry)
                    if canceled() or (isinstance(netdiscover_entry.get("data"), dict) and netdiscover_entry["data"].get("canceled")):
                        agg["canceled"] = True
                        agg["finished_at"] = time.time()
                        return agg

                aircrack_entry = run_aircrack_if_requested()
                if aircrack_entry is not None:
                    agg["results"].append(aircrack_entry)
                    if canceled() or (isinstance(aircrack_entry.get("data"), dict) and aircrack_entry["data"].get("canceled")):
                        agg["canceled"] = True
                        agg["finished_at"] = time.time()
                        return agg

                scoutsuite_entry = run_scoutsuite_if_requested()
                if scoutsuite_entry is not None:
                    agg["results"].append(scoutsuite_entry)
                    if canceled() or (isinstance(scoutsuite_entry.get("data"), dict) and scoutsuite_entry["data"].get("canceled")):
                        agg["canceled"] = True
                        agg["finished_at"] = time.time()
                        return agg

                prowler_entry = run_prowler_if_requested()
                if prowler_entry is not None:
                    agg["results"].append(prowler_entry)
                    if canceled() or (isinstance(prowler_entry.get("data"), dict) and prowler_entry["data"].get("canceled")):
                        agg["canceled"] = True
                        agg["finished_at"] = time.time()
                        return agg

                tls_ports = self._tls_candidate_ports_from_nmap(
                    nmap_entry.get("data", {}).get("scan_data", {}),
                    web_targets=web_targets,
                )
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
                    agg["results"].append(self._skip_tool("sslscan", "No TLS candidate ports detected from discovery"))

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

            if not lock_web_targets and not web_targets and nmap_entry.get("success"):
                web_targets = []

            if nmap_entry.get("success"):
                # Domain enumeration (opt-in): expand candidates beyond nmap-derived ports.
                if (not lock_web_targets) and self._tool_enabled("subfinder", default=False) and self._has_scanner("subfinder") and self._should_run_dnsenum(scan_host):
                    subfinder_entry = run_subfinder(scan_host)
                    agg["results"].append(subfinder_entry)
                    if subfinder_entry.get("success"):
                        hosts = subfinder_entry.get("data", {}).get("hosts", [])
                        if isinstance(hosts, list) and hosts:
                            # Bound the candidate explosion to keep httpx reasonable.
                            for h in [str(x).strip() for x in hosts[:50] if str(x).strip()]:
                                web_targets.append(f"http://{h}")
                                web_targets.append(f"https://{h}")

                # Always include nmap-derived web targets too.
                if not lock_web_targets:
                    derived = self._web_targets_from_nmap(scan_host, nmap_entry.get("data", {}).get("scan_data", {}))
                    for u in derived:
                        if u not in web_targets:
                            web_targets.append(u)
                    agg["web_targets"] = web_targets

            # Probe derived web targets (best-effort) to avoid false-positives from service detection.
            if web_targets and self._has_scanner("httpx"):
                note("tool_start", "httpx", "Probing web targets with httpx")
                httpx_entry = self._run_tool_if_enabled(
                    "httpx",
                    lambda: self.scanners["httpx"].scan(
                        web_targets,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("httpx"),
                    ),
                )
                agg["results"].append(httpx_entry)
                note("tool_end", "httpx", "Finished httpx")
                if httpx_entry.get("success"):
                    alive = httpx_entry.get("data", {}).get("alive")
                    if isinstance(alive, list) and alive:
                        web_targets = [str(x) for x in alive if str(x).strip()]
                        agg["web_targets"] = web_targets

            # Post-recon conditional modules
            if nmap_entry.get("success"):
                open_ports = self._open_ports_from_nmap(nmap_entry.get("data", {}).get("scan_data", {}))
                agg["open_ports"] = open_ports
                for entry in run_hydra_from_nmap(nmap_entry):
                    agg["results"].append(entry)
                for entry in run_searchsploit_from_nmap(nmap_entry):
                    agg["results"].append(entry)
                for entry in run_medusa_from_nmap(nmap_entry):
                    agg["results"].append(entry)
                for entry in run_crackmapexec_from_nmap(nmap_entry):
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
                    agg["results"].append(self._skip_tool("dnsenum", self._dns_target_skip_reason(scan_host)))

                # TLS scan (TLS/HTTPS candidate ports, incl. non-standard)
                tls_ports = self._tls_candidate_ports_from_nmap(
                    nmap_entry.get("data", {}).get("scan_data", {}),
                    web_targets=web_targets,
                )
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
                    agg["results"].append(self._skip_tool("sslscan", "No TLS candidate ports detected from discovery"))

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

            harvester_entry = run_theharvester_if_requested(scan_host)
            if harvester_entry is not None:
                agg["results"].append(harvester_entry)
                if canceled() or (isinstance(harvester_entry.get("data"), dict) and harvester_entry["data"].get("canceled")):
                    agg["canceled"] = True
                    agg["finished_at"] = time.time()
                    return agg

            netdiscover_entry = run_netdiscover_if_requested()
            if netdiscover_entry is not None:
                agg["results"].append(netdiscover_entry)
                if canceled() or (isinstance(netdiscover_entry.get("data"), dict) and netdiscover_entry["data"].get("canceled")):
                    agg["canceled"] = True
                    agg["finished_at"] = time.time()
                    return agg

            aircrack_entry = run_aircrack_if_requested()
            if aircrack_entry is not None:
                agg["results"].append(aircrack_entry)
                if canceled() or (isinstance(aircrack_entry.get("data"), dict) and aircrack_entry["data"].get("canceled")):
                    agg["canceled"] = True
                    agg["finished_at"] = time.time()
                    return agg

            scoutsuite_entry = run_scoutsuite_if_requested()
            if scoutsuite_entry is not None:
                agg["results"].append(scoutsuite_entry)
                if canceled() or (isinstance(scoutsuite_entry.get("data"), dict) and scoutsuite_entry["data"].get("canceled")):
                    agg["canceled"] = True
                    agg["finished_at"] = time.time()
                    return agg

            prowler_entry = run_prowler_if_requested()
            if prowler_entry is not None:
                agg["results"].append(prowler_entry)
                if canceled() or (isinstance(prowler_entry.get("data"), dict) and prowler_entry["data"].get("canceled")):
                    agg["canceled"] = True
                    agg["finished_at"] = time.time()
                    return agg

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
                agg["results"].append(self._skip_tool("wpscan", "No web ports detected (80/443/8080/8443)"))

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

        # Supabase security audit (URLs/keys/RPC exposure)
        if web_targets and self._has_scanner("supabase_audit"):
            if canceled():
                agg["canceled"] = True
                agg["finished_at"] = time.time()
                return agg
            supabase_cfg = self._tool_config("supabase_audit")
            max_pages = supabase_cfg.get("max_pages", 5)
            try:
                max_pages = int(max_pages)
            except Exception:
                max_pages = 5
            max_pages = max(1, max_pages)
            extra_urls: List[str] = []
            cfg_extra = supabase_cfg.get("extra_urls")
            if isinstance(cfg_extra, str):
                extra_urls.extend([u.strip() for u in cfg_extra.split(",") if u.strip()])
            elif isinstance(cfg_extra, list):
                extra_urls.extend([str(u).strip() for u in cfg_extra if str(u).strip()])
            env_extra = os.getenv("SUPABASH_SUPABASE_URLS", "").strip()
            if env_extra:
                extra_urls.extend([u.strip() for u in env_extra.split(",") if u.strip()])
            note("tool_start", "supabase_audit", "Running supabase security checks")
            agg["results"].append(
                self._run_tool_if_enabled(
                    "supabase_audit",
                    lambda: self.scanners["supabase_audit"].scan(
                        web_targets,
                        max_pages=max_pages,
                        supabase_urls_override=extra_urls or None,
                        cancel_event=cancel_event,
                        timeout_seconds=self._tool_timeout_seconds("supabase_audit"),
                    ),
                )
            )
            note("tool_end", "supabase_audit", "Finished supabase security checks")

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

        ffuf_fallback_hits = []
        for entry in agg.get("results", []) or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("tool") != "ffuf" or entry.get("fallback_for") != "gobuster":
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

        findings = self._collect_findings(agg)
        if llm_enabled:
            note("llm_start", "summary", "Summarizing with LLM")
            ctx = self._build_llm_summary_context(agg, findings)
            summary, llm_meta = self._summarize_with_llm(agg, context=ctx)
            if llm_meta:
                self._append_llm_call(agg, llm_meta)
                if llm_meta.get("error"):
                    note("llm_error", "summary", f"LLM summary failed: {llm_meta['error']}")
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
        findings = self._apply_compliance_tags(agg, findings, normalized_compliance)
        agg["findings"] = findings
        agg["finished_at"] = time.time()
        try:
            annotate_schema_validation(agg, kind="audit")
        except Exception:
            pass

        if output is not None:
            # Persist tool artifacts + manifest for audit-prep reproducibility.
            self._write_evidence_pack(agg, output)
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
