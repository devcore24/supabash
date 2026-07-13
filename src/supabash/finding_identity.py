from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Tuple
from urllib.parse import urlparse


def normalize_finding_text(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"\b[0-9a-f]{24,}\b", "<hex>", text)
    text = re.sub(r"\b\d{8,}\b", "<num>", text)
    return re.sub(r"\s+", " ", text)


def extract_finding_host_path(finding: Dict[str, Any]) -> Tuple[str, str]:
    text = " ".join(
        [str(finding.get("title") or "").strip(), str(finding.get("evidence") or "").strip()]
    ).strip()

    def parse_candidate_url(candidate_text: Any) -> Tuple[str, str]:
        candidate = str(candidate_text or "").strip().rstrip(".,;")
        if not candidate:
            return "", ""
        try:
            parsed = urlparse(candidate)
            host = str(parsed.hostname or "").strip().lower()
            path = str(parsed.path or "/").strip()
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return host, path
        except Exception:
            return "", ""

    if text:
        url_match = re.search(r"https?://[^\s)>'\"`]+", text, flags=re.IGNORECASE)
        if url_match:
            host, path = parse_candidate_url(url_match.group(0))
            if host:
                return host, path

    target_hint = str(finding.get("target") or "").strip()
    if target_hint:
        host, path = parse_candidate_url(target_hint)
        if host:
            return host, path
    if not text:
        return "", ""

    host_match = re.search(r"\bhost=([a-z0-9._:-]+)\b", text, flags=re.IGNORECASE)
    host = str(host_match.group(1)).strip().lower() if host_match else ""
    path_match = re.search(r"\bpath=(/[^\s,;)]*)", text, flags=re.IGNORECASE)
    if path_match:
        return host, str(path_match.group(1)).strip()
    endpoint_match = re.search(r"\s(/[a-z0-9._~!$&'()*+,;=:@%/-]{2,})", text, flags=re.IGNORECASE)
    if endpoint_match:
        return host, str(endpoint_match.group(1)).strip()
    return host, ""


def classify_finding_risk_class(finding: Dict[str, Any]) -> str:
    tool = str(finding.get("tool") or "").strip().lower()
    title = normalize_finding_text(finding.get("title"))
    evidence = normalize_finding_text(finding.get("evidence"))
    kind = normalize_finding_text(finding.get("type"))
    joined = " ".join(value for value in (title, evidence, kind) if value)

    if any(key in joined for key in ("service role key", "secret", "token", "password", "credential", "api key")):
        return "secret_exposure"
    if any(key in joined for key in ("sql injection", "xss", "rce", "cve", "vulnerability", "auth bypass")):
        return "known_vulnerability"
    if any(key in joined for key in ("tls", "ssl", "cipher", "certificate", "cleartext", "https")):
        return "transport_security"
    if any(
        key in joined
        for key in ("without authentication", "unauthenticated", "anonymous", "publicly accessible", "exposed", "open port")
    ):
        return "unauthenticated_exposure"
    if any(key in joined for key in ("redis", "postgres", "database", "rest api", "rpc", "rls")):
        return "data_plane_exposure"
    if any(key in joined for key in ("missing security headers", "misconfig", "configuration", "default")):
        return "security_misconfiguration"
    if tool in ("sqlmap", "nuclei", "trivy", "wpscan", "browser_use"):
        return "vulnerability_signal"
    if tool in ("hydra", "medusa", "crackmapexec"):
        return "credential_access"
    if tool == "sslscan":
        return "transport_security"
    if tool in ("nmap", "httpx", "whatweb", "subfinder", "katana", "gobuster", "ffuf"):
        return "surface_discovery"
    if tool in ("dnsenum", "theharvester", "netdiscover"):
        return "asset_discovery"
    return "general_security_signal"


def finding_dedup_key(finding: Dict[str, Any]) -> str:
    explicit = str(finding.get("dedup_key") or "").strip()
    if explicit:
        return explicit
    tool = normalize_finding_text(finding.get("tool")) or "-"
    severity = str(finding.get("severity") or "INFO").strip().upper() or "INFO"
    template = normalize_finding_text(finding.get("type")) or normalize_finding_text(finding.get("title"))
    host, path = extract_finding_host_path(finding)
    evidence_norm = normalize_finding_text(finding.get("evidence"))
    evidence_hash = hashlib.sha256(evidence_norm.encode("utf-8")).hexdigest()[:16] if evidence_norm else "0" * 16
    return "|".join([tool, template or "-", host or "-", path or "-", severity, evidence_hash])
