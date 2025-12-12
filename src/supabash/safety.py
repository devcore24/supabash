import ipaddress
from fnmatch import fnmatch
from typing import List
from urllib.parse import urlparse


def _extract_host(value: str) -> str:
    """
    Extract hostname from a URL-like input; otherwise return the original value.
    """
    if "://" in value:
        try:
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            return value
    return value


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _match_network(target: str, allowed: str) -> bool:
    try:
        net = ipaddress.ip_network(allowed, strict=False)
        return ipaddress.ip_address(target) in net
    except ValueError:
        return False


def is_public_ip_target(target: str) -> bool:
    """
    Returns True when the target is (or contains) a public/global IP address.
    Only checks IP-literal inputs (or URL hosts that are IP literals).
    """
    host = _extract_host(target).strip()
    # Handle IPv6 bracketed literals like "[2001:db8::1]"
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(getattr(ip, "is_global", False))


def is_allowed_target(target: str, allowed_hosts: List[str]) -> bool:
    """
    Returns True if target matches allowed hosts/IPs/CIDRs exactly, matches a wildcard pattern,
    or falls within an allowed CIDR.
    """
    if not allowed_hosts:
        return False
    # Accept URLs by extracting hostname
    target = _extract_host(target)
    target_norm = target.strip().lower()
    if not target_norm:
        return False

    for raw_entry in allowed_hosts:
        if not raw_entry:
            continue
        entry = str(raw_entry).strip()
        if not entry:
            continue

        # Allow URL entries by extracting hostname
        entry = _extract_host(entry)

        entry_norm = entry.lower()

        # Exact match for hostnames/IPs
        if target_norm == entry_norm:
            return True

        # Wildcard patterns for hostnames
        if ("*" in entry_norm or "?" in entry_norm) and fnmatch(target_norm, entry_norm):
            return True

        # CIDR match for IPs
        if _is_ip(target_norm) and "/" in entry_norm and _match_network(target_norm, entry_norm):
            return True
    return False


def require_consent(assume_yes: bool = False) -> bool:
    """
    Prompt user for consent unless assume_yes is True.
    """
    if assume_yes:
        return True
    try:
        resp = input("This action may scan targets. Do you have authorization? [y/N]: ").strip().lower()
        return resp in ("y", "yes")
    except EOFError:
        return False


def ensure_consent(config_manager, assume_yes: bool = False) -> bool:
    """
    Persist consent in config on the first interactive acceptance.
    If assume_yes is True, do not persist (useful for non-interactive runs/tests).
    """
    if config_manager is None:
        return require_consent(assume_yes=assume_yes)

    core = config_manager.config.setdefault("core", {})
    if core.get("consent_accepted") is True:
        return True

    if assume_yes:
        return True

    if require_consent():
        core["consent_accepted"] = True
        config_manager.save_config(config_manager.config)
        return True

    return False
