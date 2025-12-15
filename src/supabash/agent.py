from dataclasses import dataclass, field
from typing import List, Dict, Any
import ipaddress


@dataclass
class AgentState:
    target: str
    ports: List[Dict[str, Any]] = field(default_factory=list)
    tech: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    actions_run: List[str] = field(default_factory=list)


class MethodologyPlanner:
    """
    Heuristic planner that suggests next tools based on current state/fingerprints.
    """

    def suggest(self, state: AgentState) -> Dict[str, Any]:
        actions = []
        notes = []

        target = (state.target or "").strip()
        is_domainish = False
        if target and "." in target and "/" not in target and ":" not in target:
            try:
                ipaddress.ip_address(target)
            except Exception:
                is_domainish = True

        # Recon branching: open web ports
        web_ports = [p for p in state.ports if p.get("port") in (80, 443, 8080, 8443) and p.get("state") == "open"]
        if web_ports:
            actions.append("httpx")
            notes.append("Web ports open: probe HTTP(S) endpoints with httpx to confirm live URLs.")
            actions.append("whatweb")
            actions.append("nuclei")
            actions.append("gobuster")
            notes.append("Web ports open: run tech detection, nuclei templates, and content discovery.")
            if any(p.get("port") in (443, 8443) for p in web_ports):
                actions.append("sslscan")
                notes.append("HTTPS detected: run sslscan for TLS configuration issues.")
            actions.append("nikto")
            notes.append("Nikto is slow/noisy: enable only if needed.")

        if any(p.get("port") in (139, 445) and p.get("state") == "open" for p in state.ports):
            actions.append("enum4linux-ng")
            notes.append("SMB detected: consider enum4linux-ng for SMB enumeration.")

        if is_domainish:
            actions.append("dnsenum")
            notes.append("Domain target: consider dnsenum for DNS enumeration.")

        # Auth/brute possibilities
        if any(p.get("port") == 22 and p.get("state") == "open" for p in state.ports):
            actions.append("hydra:ssh")
            notes.append("SSH open: consider credential testing (within scope).")
        if any(p.get("port") in (21, 25, 143, 110, 389) and p.get("state") == "open" for p in state.ports):
            actions.append("hydra:other")
            notes.append("Auth services open: consider targeted brute/enum.")

        # Databases
        if any(p.get("port") == 3306 and p.get("state") == "open" for p in state.ports):
            actions.append("sqlmap:mysql")
            notes.append("MySQL open: check for SQLi on connected apps/params.")

        # Container
        if "container_image" in (f.get("type") for f in state.findings):
            actions.append("trivy")
            notes.append("Container image provided: run Trivy for CVEs/misconfigs.")

        # Defaults if nothing else
        if not actions:
            actions.append("nmap:full")
            notes.append("No signals yet: escalate to full nmap or targeted vuln scan.")

        return {"next_steps": actions, "notes": " ".join(notes)}
