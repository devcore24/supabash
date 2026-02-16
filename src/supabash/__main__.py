import typer
import shlex
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import os
import sys
import shutil
import importlib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from supabash.logger import setup_logger
from supabash.config import config_manager
from supabash.tools.nmap import NmapScanner
from supabash.tools.masscan import MasscanScanner
from supabash.tools.rustscan import RustscanScanner
from supabash.chat import ChatSession
from supabash.safety import is_allowed_target, is_public_ip_target
from supabash.audit import AuditOrchestrator, COMPLIANCE_PROFILE_ALIASES, COMPLIANCE_PROFILES
from supabash.ai_audit import AIAuditOrchestrator
from supabash.session_state import default_chat_state_path, clear_state as clear_session_state
from supabash.report_paths import build_report_paths
from supabash.slash_parse import normalize_target_token
from supabash.tool_settings import get_tool_timeout_seconds

app = typer.Typer(
    name="supabash",
    help="Supabash: The Autonomous AI Security Audit Agent",
    add_completion=False,
)
console = Console()
core_config = config_manager.config.get("core", {})
log_level = core_config.get("log_level", "INFO")
logger = setup_logger(log_level=log_level)


def _compliance_slug(profile: Optional[str]) -> Optional[str]:
    if not profile:
        return None
    token = str(profile).strip().lower().replace(" ", "_")
    if not token:
        return None
    if token in COMPLIANCE_PROFILE_ALIASES:
        token = COMPLIANCE_PROFILE_ALIASES[token]
    elif token.startswith("compliance_"):
        token = token if token in COMPLIANCE_PROFILES else None
    else:
        candidate = f"compliance_{token}"
        token = candidate if candidate in COMPLIANCE_PROFILES else None
    if not token:
        return None
    return token.replace("compliance_", "")

SCANNERS = {
    "nmap": NmapScanner,
    "masscan": MasscanScanner,
    "rustscan": RustscanScanner,
}

BANNER = r"""
   _____                   _               _     
  / ____|                 | |             | |    
 | (___  _   _ _ __   __ _| |__   __ _ ___| |__  
  \___ \| | | | '_ \ / _` | '_ \ / _` / __| '_ \ 
  ____) | |_| | |_) | (_| | |_) | (_| \__ \ | | |
 |_____/ \__,_| .__/ \__,_|_.__/ \__,_|___/_| |_|
              | |                                
              |_|                                
"""

def print_banner():
    text = Text(BANNER, style="bold cyan")
    panel = Panel(text, border_style="bold blue", title="v0.1.0-beta", subtitle="AI Security Agent")
    console.print(panel)

def _report_formats_note(config: Optional[dict]) -> str:
    cfg = config if isinstance(config, dict) else {}
    core = cfg.get("core", {}) if isinstance(cfg.get("core", {}), dict) else {}
    exports = core.get("report_exports", {}) if isinstance(core.get("report_exports", {}), dict) else {}
    formats = []
    if exports.get("html"):
        formats.append("html")
    formats.append("md")
    if exports.get("pdf"):
        formats.append("pdf")
    if not formats:
        return ""
    if len(formats) == 1:
        return f" (and in {formats[0]} files)"
    if len(formats) == 2:
        return f" (and in {formats[0]} and {formats[1]} files)"
    return f" (and in {formats[0]}, {formats[1]}, and {formats[2]} files)"

def _only_top_level_help_invocation(argv: list[str]) -> bool:
    """
    Return True when the user invoked only top-level help (e.g. `supabash --help`).
    We intentionally do not intercept `supabash <command> --help`.
    """
    try:
        args = list(argv[1:])
    except Exception:
        return False
    if not args:
        return False
    if not any(a in ("--help", "-h") for a in args):
        return False
    # Any non-flag token implies a subcommand; do not intercept.
    for a in args:
        if a == "--":
            continue
        if a in ("--help", "-h"):
            continue
        if not str(a).startswith("-"):
            return False
    return True

def _print_extended_help() -> None:
    """
    Print an extended top-level help that includes per-command parameters.
    """
    try:
        import click
        from typer.main import get_command as _get_typer_command
    except Exception:
        # Fall back to Typer's default help.
        raise

    root_cmd = _get_typer_command(app)
    root_ctx = click.Context(root_cmd, info_name=str(getattr(root_cmd, "name", "supabash") or "supabash"))

    console.print(f"[bold]Usage:[/bold] {root_ctx.info_name} [OPTIONS] COMMAND [ARGS]...\n")
    if getattr(root_cmd, "help", None):
        console.print(str(root_cmd.help).strip() + "\n")

    # Global options (best-effort)
    try:
        opts_table = Table(title="Global Options", show_header=True, header_style="bold magenta")
        opts_table.add_column("Option", style="cyan", no_wrap=True)
        opts_table.add_column("Description")
        for param in root_cmd.get_params(root_ctx):
            rec = param.get_help_record(root_ctx)
            if not rec:
                continue
            left, right = rec
            opts_table.add_row(str(left), str(right or ""))
        console.print(opts_table)
        console.print()
    except Exception:
        pass

    # Commands list
    try:
        commands = getattr(root_cmd, "commands", {}) or {}
        cmd_table = Table(title="Commands", show_header=True, header_style="bold magenta")
        cmd_table.add_column("Command", style="cyan", no_wrap=True)
        cmd_table.add_column("Description")
        for name in sorted(commands.keys()):
            cmd = commands[name]
            desc = ""
            try:
                desc = cmd.get_short_help_str(limit=90)
            except Exception:
                desc = (getattr(cmd, "help", "") or "").strip().splitlines()[0] if getattr(cmd, "help", None) else ""
            cmd_table.add_row(str(name), str(desc))
        console.print(cmd_table)
        console.print()
    except Exception:
        commands = {}

    # Per-command parameters
    try:
        if not commands:
            return
        console.print("[bold]Command Parameters[/bold]")
        console.print("[dim]Tip: run `supabash <command> --help` for full per-command help text.[/dim]\n")
        for name in sorted(commands.keys()):
            cmd = commands[name]
            title = f"{root_ctx.info_name} {name}"
            panel_lines: list[str] = []
            help_str = (getattr(cmd, "help", "") or "").strip()
            if help_str:
                panel_lines.append(help_str.splitlines()[0])

            subctx = click.Context(cmd, info_name=title, parent=root_ctx)
            params = cmd.get_params(subctx)

            args = [p for p in params if getattr(p, "param_type_name", "") == "argument"]
            opts = [p for p in params if getattr(p, "param_type_name", "") == "option"]

            if args:
                panel_lines.append("\nArguments:")
                for a in args:
                    arg_name = getattr(a, "name", "arg")
                    required = " (required)" if getattr(a, "required", False) else ""
                    panel_lines.append(f"- <{arg_name}>{required}")

            if opts:
                panel_lines.append("\nOptions:")
                for o in opts:
                    rec = o.get_help_record(subctx)
                    if rec:
                        left, right = rec
                        panel_lines.append(f"- {left} — {right or ''}".rstrip())
                    else:
                        # Fallback formatting
                        flags = []
                        for f in getattr(o, "opts", []) + getattr(o, "secondary_opts", []):
                            flags.append(f)
                        panel_lines.append(f"- {', '.join(flags)}")

            if not args and not opts:
                panel_lines.append("\n(no parameters)")

            console.print(Panel("\n".join(panel_lines).strip(), title=name, border_style="cyan"))
    except Exception:
        pass

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Supabash Entry Point.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[bold green]Welcome to Supabash![/bold green]")
        console.print("Use [bold cyan]--help[/bold cyan] to see full list of commands and params.")

        # Print a compact command list (best-effort).
        try:
            commands = getattr(ctx.command, "commands", {}) or {}
            if isinstance(commands, dict) and commands:
                table = Table(title="Commands", show_header=True, header_style="bold magenta")
                table.add_column("Command", style="cyan", no_wrap=True)
                table.add_column("Description")
                for name in sorted(commands.keys()):
                    cmd = commands[name]
                    short = ""
                    try:
                        short = cmd.get_short_help_str(limit=80)
                    except Exception:
                        short = getattr(cmd, "help", "") or ""
                        short = (short.strip().splitlines()[0] if isinstance(short, str) and short else "")
                    table.add_row(str(name), str(short))
                console.print(table)
        except Exception:
            pass

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or Domain to scan"),
    profile: str = typer.Option("fast", "--profile", "-p", help="Scan profile: fast, full, stealth"),
    scanner_name: str = typer.Option("nmap", "--scanner", "-s", help="Scanner engine: nmap, masscan, rustscan"),
    allow_unsafe: bool = typer.Option(False, "--force", help="Bypass allowed-hosts safety check"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public IP targets (requires authorization)"),
    consent: bool = typer.Option(False, "--yes", help="Skip consent prompt"),
    masscan_rate: int = typer.Option(0, "--masscan-rate", help="Override masscan rate (pps)"),
    rustscan_batch: int = typer.Option(0, "--rustscan-batch", help="Override rustscan batch size"),
):
    """
    Launch a basic reconnaissance scan against a target.
    """
    allowed = config_manager.config.get("core", {}).get("allowed_hosts", [])
    if not allow_unsafe and not is_allowed_target(target, allowed):
        console.print(f"[red]Target '{target}' not in allowed_hosts. Edit config.yaml or use --force to proceed.[/red]")
        raise typer.Exit(code=1)

    allow_public_cfg = bool(config_manager.config.get("core", {}).get("allow_public_ips", False))
    if is_public_ip_target(target) and not (allow_public_cfg or allow_public):
        console.print(
            "[red]Refusing to scan public IP targets by default.[/red] "
            "Set `core.allow_public_ips=true` in `config.yaml` or pass `--allow-public` (only if you are authorized)."
        )
        raise typer.Exit(code=1)
    from supabash.safety import ensure_consent
    if not ensure_consent(config_manager, assume_yes=consent):
        console.print("[yellow]Consent not confirmed. Aborting.[/yellow]")
        raise typer.Exit(code=1)

    scanner_name = scanner_name.lower()
    if scanner_name not in SCANNERS:
        console.print(f"[red]Unknown scanner '{scanner_name}'. Choose from: {', '.join(SCANNERS.keys())}[/red]")
        raise typer.Exit(code=1)

    logger.info(f"Command 'scan' triggered for target: {target} with profile: {profile} using {scanner_name}")
    console.print(f"[bold blue][*] Starting {profile} scan against {target} with {scanner_name}...[/bold blue]")

    scanner_cls = SCANNERS[scanner_name]
    scanner = scanner_cls()

    # Determine scan parameters based on scanner
    ports = None
    args = None
    extra_kwargs = {}

    if scanner_name == "nmap":
        args = "-sV -O"  # Default: Service + OS detection
        if profile == "fast":
            args += " -F"  # Fast scan mode (top 100 ports)
        elif profile == "full":
            ports = "1-65535"
            args += " -T4"  # Faster execution for full scan
        elif profile == "stealth":
            args = "-sS -T2"  # Syn scan, slower timing
    elif scanner_name == "masscan":
        ports = "1-1000"
        rate = masscan_rate if masscan_rate > 0 else 1000
        if profile == "full":
            ports = "1-65535"
            rate = masscan_rate if masscan_rate > 0 else 5000
        elif profile == "stealth":
            rate = masscan_rate if masscan_rate > 0 else 100
        extra_kwargs["rate"] = rate
    elif scanner_name == "rustscan":
        ports = "1-1000"
        batch = rustscan_batch if rustscan_batch > 0 else 2000
        if profile == "full":
            ports = "1-65535"
            batch = rustscan_batch if rustscan_batch > 0 else 5000
        elif profile == "stealth":
            batch = rustscan_batch if rustscan_batch > 0 else 1000
        extra_kwargs["batch"] = batch

    status_msg = f"[bold green]Running {scanner_name} ({profile})... This may take a moment.[/bold green]"
    with console.status(status_msg):
        tool_timeout = get_tool_timeout_seconds(config_manager.config, scanner_name)
        if scanner_name == "nmap":
            result = scanner.scan(target, ports=ports, arguments=args, timeout_seconds=tool_timeout)
        elif scanner_name == "masscan":
            result = scanner.scan(target, ports=ports, rate=extra_kwargs["rate"], arguments=args, timeout_seconds=tool_timeout)
        else:
            result = scanner.scan(target, ports=ports, batch=extra_kwargs["batch"], arguments=args, timeout_seconds=tool_timeout)

    if not result["success"]:
        error_msg = result.get('error', '')
        console.print(f"[bold red][!] Scan Failed:[/bold red] {error_msg}")
        
        if scanner_name == "nmap" and ("root privileges" in error_msg or "permission denied" in error_msg.lower()):
            console.print("\n[yellow][bulb] Hint: Nmap OS detection (-O) and SYN scans (-sS) require root privileges.[/yellow]")
            console.print("[yellow]       Try running: [bold]sudo supabash scan ...[/bold][/yellow]")
        return
    warnings = result.get("warnings")
    if scanner_name == "nmap" and isinstance(warnings, list) and warnings:
        for w in warnings:
            console.print(f"[yellow][!] {w}[/yellow]")

    data = result["scan_data"]
    if not data["hosts"]:
        console.print("[yellow][!] No hosts found or host is down.[/yellow]")
        return

    # Display Results
    for host in data["hosts"]:
        ip = host.get("ip", "unknown")
        hostnames = ", ".join(host.get("hostnames", []))
        os_matches = host.get("os", [])
        os_name = os_matches[0]["name"] if os_matches else "Unknown"
        
        console.print(Panel(f"[bold]Target:[/bold] {ip} ({hostnames})\n[bold]OS:[/bold] {os_name}", title="Scan Results", border_style="green"))
        
        ports_list = host.get("ports", [])
        if ports_list:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Port")
            table.add_column("State")
            table.add_column("Service")
            table.add_column("Info")

            for p in ports_list:
                port_num = p.get("port", "")
                state = p.get("state", "")
                service = p.get("service", "")
                product = p.get("product", "")
                version = p.get("version", "")
                protocol = p.get("protocol", "")
                details = " ".join(filter(None, [product, version, protocol])).strip()
                table.add_row(str(port_num), state, service, details)
            
            console.print(table)
        else:
            console.print("[yellow]No open ports found.[/yellow]")

@app.command()
def audit(
    target: str = typer.Argument(..., help="Target IP, URL, or Container ID"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Output JSON path (default: reports/<slug>/<slug>.json; "
            "where slug is report-YYYYmmdd-HHMMSS, or ai-audit(-<profile>)-YYYYmmdd-HHMMSS when --agentic is set)"
        ),
    ),
    container_image: str = typer.Option(None, "--container-image", "-c", help="Optional container image to scan with Trivy"),
    markdown: Optional[str] = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Output Markdown path (default: derived from --output with .md)",
    ),
    status: bool = typer.Option(True, "--status/--no-status", help="Print live progress updates during the run"),
    status_file: Optional[str] = typer.Option(None, "--status-file", help="Write JSON status updates to this file while running"),
    allow_unsafe: bool = typer.Option(False, "--force", help="Bypass allowed-hosts safety check"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public IP targets (requires authorization)"),
    consent: bool = typer.Option(False, "--yes", help="Skip consent prompt"),
    mode: str = typer.Option("normal", "--mode", help="Scan mode: normal|stealth|aggressive"),
    compliance: Optional[str] = typer.Option(
        None,
        "--compliance",
        help="Compliance profile for audit planning (pci, soc2, iso, dora, nis2, gdpr, bsi)",
    ),
    nuclei_rate_limit: int = typer.Option(0, "--nuclei-rate", help="Nuclei request rate limit (per second)"),
    nuclei_tags: str = typer.Option(None, "--nuclei-tags", help="Comma-separated Nuclei template tags"),
    nuclei_severity: str = typer.Option(None, "--nuclei-severity", help="Comma-separated Nuclei severities (e.g. low,medium,high)"),
    gobuster_threads: int = typer.Option(10, "--gobuster-threads", help="Gobuster thread count"),
    gobuster_wordlist: str = typer.Option(None, "--gobuster-wordlist", help="Gobuster wordlist path"),
    parallel_web: bool = typer.Option(False, "--parallel-web", help="Run web tools in parallel (URL targets can overlap with recon)"),
    max_workers: int = typer.Option(3, "--max-workers", help="Max concurrent workers when --parallel-web is enabled"),
    nikto: bool = typer.Option(False, "--nikto", help="Run Nikto web scan (slow; opt-in)"),
    hydra: bool = typer.Option(False, "--hydra", help="Run Hydra bruteforce (opt-in; requires explicit wordlists)"),
    hydra_usernames: Optional[str] = typer.Option(None, "--hydra-usernames", help="Hydra usernames (path to file or single username)"),
    hydra_passwords: Optional[str] = typer.Option(None, "--hydra-passwords", help="Hydra passwords (path to file or single password)"),
    hydra_services: str = typer.Option("ssh,ftp", "--hydra-services", help="Comma-separated hydra services (e.g. ssh,ftp)"),
    hydra_threads: int = typer.Option(4, "--hydra-threads", help="Hydra parallel tasks (-t)"),
    hydra_options: Optional[str] = typer.Option(None, "--hydra-options", help="Extra Hydra CLI options (advanced)"),
    medusa: bool = typer.Option(False, "--medusa", help="Run Medusa bruteforce (opt-in; requires explicit wordlists)"),
    medusa_usernames: Optional[str] = typer.Option(None, "--medusa-usernames", help="Medusa usernames (path to file or single username)"),
    medusa_passwords: Optional[str] = typer.Option(None, "--medusa-passwords", help="Medusa passwords (path to file or single password)"),
    medusa_module: Optional[str] = typer.Option(None, "--medusa-module", help="Medusa module/service (default: derived from nmap)"),
    medusa_port: Optional[int] = typer.Option(None, "--medusa-port", help="Medusa target port (default: derived from nmap)"),
    medusa_threads: int = typer.Option(4, "--medusa-threads", help="Medusa parallel threads (-t)"),
    medusa_timeout: int = typer.Option(10, "--medusa-timeout", help="Medusa timeout per connection (seconds)"),
    medusa_options: Optional[str] = typer.Option(None, "--medusa-options", help="Extra Medusa CLI options (advanced)"),
    crackmapexec: bool = typer.Option(False, "--crackmapexec", "--cme", help="Run CrackMapExec/NetExec (opt-in)"),
    cme_protocol: str = typer.Option("smb", "--cme-protocol", help="CME protocol (smb, ssh, ldap, winrm, mssql, rdp)"),
    cme_username: Optional[str] = typer.Option(None, "--cme-username", help="CME username"),
    cme_password: Optional[str] = typer.Option(None, "--cme-password", help="CME password"),
    cme_domain: Optional[str] = typer.Option(None, "--cme-domain", help="CME domain"),
    cme_hashes: Optional[str] = typer.Option(None, "--cme-hashes", help="CME NTLM hashes (LM:NT or NT)"),
    cme_module: Optional[str] = typer.Option(None, "--cme-module", help="CME module to run"),
    cme_module_options: Optional[str] = typer.Option(None, "--cme-module-options", help="CME module options"),
    cme_enum: Optional[str] = typer.Option(None, "--cme-enum", help="CME enumeration flags (comma-separated; e.g. shares,users)"),
    cme_args: Optional[str] = typer.Option(None, "--cme-args", help="Extra CME CLI arguments (allows anonymous runs)"),
    scoutsuite: bool = typer.Option(False, "--scoutsuite", help="Run ScoutSuite (multi-cloud; opt-in)"),
    scoutsuite_provider: str = typer.Option("aws", "--scoutsuite-provider", help="ScoutSuite provider (aws, azure, gcp)"),
    scoutsuite_args: Optional[str] = typer.Option(None, "--scoutsuite-args", help="Extra ScoutSuite CLI arguments"),
    prowler: bool = typer.Option(False, "--prowler", help="Run Prowler (AWS; opt-in)"),
    prowler_args: Optional[str] = typer.Option(None, "--prowler-args", help="Extra Prowler CLI arguments"),
    theharvester: bool = typer.Option(False, "--theharvester", help="Run theHarvester OSINT (domain targets only; opt-in)"),
    theharvester_sources: Optional[str] = typer.Option(None, "--theharvester-sources", help="theHarvester data sources (comma-separated)"),
    theharvester_limit: Optional[int] = typer.Option(None, "--theharvester-limit", help="theHarvester results per source (default 500)"),
    theharvester_start: Optional[int] = typer.Option(None, "--theharvester-start", help="theHarvester start index (default 0)"),
    theharvester_args: Optional[str] = typer.Option(None, "--theharvester-args", help="Extra theHarvester CLI args"),
    netdiscover: bool = typer.Option(False, "--netdiscover", help="Run netdiscover LAN discovery (opt-in)"),
    netdiscover_range: Optional[str] = typer.Option(None, "--netdiscover-range", help="Netdiscover CIDR range (e.g. 192.168.1.0/24)"),
    netdiscover_interface: Optional[str] = typer.Option(None, "--netdiscover-interface", help="Netdiscover interface (e.g. eth0)"),
    netdiscover_passive: bool = typer.Option(False, "--netdiscover-passive", help="Netdiscover passive mode (sniff only)"),
    netdiscover_fast: bool = typer.Option(True, "--netdiscover-fast/--netdiscover-no-fast", help="Netdiscover fast mode"),
    netdiscover_args: Optional[str] = typer.Option(None, "--netdiscover-args", help="Extra netdiscover CLI args"),
    aircrack: bool = typer.Option(False, "--aircrack", "--aircrack-ng", help="Run Aircrack-ng suite (WiFi; opt-in)"),
    aircrack_interface: Optional[str] = typer.Option(None, "--aircrack-interface", help="Wireless interface for airodump-ng (e.g. wlan0mon)"),
    aircrack_channel: Optional[str] = typer.Option(None, "--aircrack-channel", help="WiFi channel to lock during capture"),
    aircrack_args: Optional[str] = typer.Option(None, "--aircrack-args", help="Extra airodump-ng CLI args"),
    aircrack_airmon: bool = typer.Option(False, "--aircrack-airmon", help="Auto start/stop monitor mode with airmon-ng"),
    remediate: bool = typer.Option(False, "--remediate", help="Use the LLM to generate concrete remediation steps + code snippets"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable LLM summary/remediation for this run (offline/no-LLM mode)"),
    agentic: bool = typer.Option(False, "--agentic", help="Run an agentic audit (baseline + tool-calling expansion)"),
    llm_plan: bool = typer.Option(
        True,
        "--llm-plan/--no-llm-plan",
        help="Use tool-calling LLM planning for agentic expansion (requires LLM enabled)",
    ),
    max_actions: int = typer.Option(10, "--max-actions", help="Maximum agentic expansion actions (only with --agentic)"),
    max_remediations: int = typer.Option(5, "--max-remediations", help="Maximum findings to remediate (cost control)"),
    min_remediation_severity: str = typer.Option("MEDIUM", "--min-remediation-severity", help="Only remediate findings at or above this severity"),
):
    """
    Run a full security audit (Infrastructure + Web + Container).
    """
    allowed = config_manager.config.get("core", {}).get("allowed_hosts", [])
    if not allow_unsafe and not is_allowed_target(target, allowed):
        console.print(f"[red]Target '{target}' not in allowed_hosts. Edit config.yaml or use --force to proceed.[/red]")
        raise typer.Exit(code=1)

    allow_public_cfg = bool(config_manager.config.get("core", {}).get("allow_public_ips", False))
    if is_public_ip_target(target) and not (allow_public_cfg or allow_public):
        console.print(
            "[red]Refusing to scan public IP targets by default.[/red] "
            "Set `core.allow_public_ips=true` in `config.yaml` or pass `--allow-public` (only if you are authorized)."
        )
        raise typer.Exit(code=1)
    if mode not in ("normal", "stealth", "aggressive"):
        console.print("[red]Invalid mode. Choose: normal, stealth, aggressive[/red]")
        raise typer.Exit(code=1)
    from supabash.safety import ensure_consent
    if not ensure_consent(config_manager, assume_yes=consent):
        console.print("[yellow]Consent not confirmed. Aborting.[/yellow]")
        raise typer.Exit(code=1)
    logger.info(f"Command 'audit' triggered for target: {target}" + (" (agentic)" if agentic else ""))
    if agentic:
        console.print(f"[bold red][*] initializing AI audit protocol for {target}...[/bold red]")
    else:
        console.print(f"[bold red][*] initializing full audit protocol for {target}...[/bold red]")
    if container_image:
        console.print(f"[dim]Including container image: {container_image}[/dim]")

    if hydra and (not hydra_usernames or not hydra_passwords):
        console.print("[red]--hydra requires --hydra-usernames and --hydra-passwords[/red]")
        raise typer.Exit(code=1)
    if medusa and (not medusa_usernames or not medusa_passwords):
        console.print("[red]--medusa requires --medusa-usernames and --medusa-passwords[/red]")
        raise typer.Exit(code=1)
    if aircrack and not aircrack_interface:
        console.print("[red]--aircrack requires --aircrack-interface[/red]")
        raise typer.Exit(code=1)
    if crackmapexec and not (cme_username or cme_password or cme_hashes or cme_args):
        console.print("[red]--crackmapexec requires creds/hashes or --cme-args for anonymous runs[/red]")
        raise typer.Exit(code=1)
    if scoutsuite:
        provider = (scoutsuite_provider or "").strip().lower()
        if provider not in ("aws", "azure", "gcp"):
            console.print("[red]--scoutsuite-provider must be one of: aws, azure, gcp[/red]")
            raise typer.Exit(code=1)

    default_base = "ai-audit" if agentic and not output else "report"
    if agentic and not output:
        compliance_slug = _compliance_slug(compliance)
        if compliance_slug:
            default_base = f"ai-audit-{compliance_slug}"
    out_path, md_path = build_report_paths(output, markdown, default_basename=default_base)

    formats_note = _report_formats_note(config_manager.config)
    console.print(f"[dim]Results will be saved to {out_path}{formats_note}[/dim]")

    status_path = Path(status_file) if status_file else None
    if status_path is not None and status_path.exists() and status_path.is_dir():
        status_name = "ai_audit_status.json" if agentic else "audit_status.json"
        status_path = status_path / status_name

    progress_cb = None
    if status or status_path is not None:
        last_line = {"event": None, "tool": None, "message": None}

        def progress_cb(event: str, tool: str, message: str, agg: dict):
            try:
                payload = {
                    "event": event,
                    "tool": tool,
                    "message": message,
                    "target": agg.get("target"),
                    "mode": agg.get("mode"),
                    "started_at": agg.get("started_at"),
                    "report_kind": agg.get("report_kind"),
                }
                if status_path is not None:
                    try:
                        status_path.parent.mkdir(parents=True, exist_ok=True)
                        status_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                    except Exception:
                        pass

                if not status:
                    return
                if (
                    last_line.get("event") == event
                    and last_line.get("tool") == tool
                    and last_line.get("message") == message
                ):
                    return
                last_line.update({"event": event, "tool": tool, "message": message})

                label = event
                if event == "tool_start":
                    label = "RUN"
                elif event == "tool_end":
                    label = "DONE"
                elif event == "tool_skip":
                    label = "SKIP"
                elif event in ("phase_start", "phase_end"):
                    label = "PHASE"
                elif event in ("llm_start", "llm_error", "llm_plan", "llm_decision", "llm_critique"):
                    label = "LLM"

                display_message = message
                if event in ("tool_start", "tool_end"):
                    action = "Evidence collection started" if event == "tool_start" else "Evidence collection completed"
                    if tool:
                        action = f"{action} ({tool})"
                    display_message = f"{action}: {message}" if message else action
                elif event in ("phase_start", "phase_end"):
                    action = "Assessment phase started" if event == "phase_start" else "Assessment phase completed"
                    if tool:
                        action = f"{action} ({tool})"
                    display_message = f"{action}: {message}" if message else action
                elif event == "llm_start":
                    display_message = f"Analyst reasoning: {message}" if message else "Analyst reasoning started"
                elif event == "llm_error":
                    display_message = f"Analyst reasoning error: {message}" if message else "Analyst reasoning error"
                elif event == "llm_plan":
                    display_message = f"Planner update: {message}" if message else "Planner update"
                elif event == "llm_decision":
                    display_message = f"Decision: {message}" if message else "Planner decision"
                elif event == "llm_critique":
                    display_message = f"Critique: {message}" if message else "Planner critique"

                tool_txt = f" {tool}" if tool else ""
                msg_txt = f": {display_message}" if display_message else ""
                if event == "llm_error":
                    console.print(f"[yellow][{label}]{tool_txt}{msg_txt}[/yellow]")
                else:
                    console.print(f"[dim][{label}]{tool_txt}{msg_txt}[/dim]")
            except Exception:
                return

    orchestrator = AIAuditOrchestrator() if agentic else AuditOrchestrator()
    run_kwargs = dict(
        container_image=container_image,
        mode=mode,
        compliance_profile=compliance,
        nuclei_rate_limit=nuclei_rate_limit,
        nuclei_tags=nuclei_tags,
        nuclei_severity=nuclei_severity,
        gobuster_threads=gobuster_threads,
        gobuster_wordlist=gobuster_wordlist,
        parallel_web=parallel_web,
        max_workers=max_workers,
        run_nikto=nikto,
        run_hydra=hydra,
        hydra_usernames=hydra_usernames,
        hydra_passwords=hydra_passwords,
        hydra_services=hydra_services,
        hydra_threads=hydra_threads,
        hydra_options=hydra_options,
        run_medusa=medusa,
        medusa_usernames=medusa_usernames,
        medusa_passwords=medusa_passwords,
        medusa_module=medusa_module,
        medusa_port=medusa_port,
        medusa_threads=medusa_threads,
        medusa_timeout=medusa_timeout,
        medusa_options=medusa_options,
        run_crackmapexec=crackmapexec,
        cme_protocol=cme_protocol,
        cme_username=cme_username,
        cme_password=cme_password,
        cme_domain=cme_domain,
        cme_hashes=cme_hashes,
        cme_module=cme_module,
        cme_module_options=cme_module_options,
        cme_enum=cme_enum,
        cme_args=cme_args,
        run_scoutsuite=scoutsuite,
        scoutsuite_provider=scoutsuite_provider,
        scoutsuite_args=scoutsuite_args,
        run_prowler=prowler,
        prowler_args=prowler_args,
        run_theharvester=theharvester,
        theharvester_sources=theharvester_sources,
        theharvester_limit=theharvester_limit,
        theharvester_start=theharvester_start,
        theharvester_args=theharvester_args,
        run_netdiscover=netdiscover,
        netdiscover_range=netdiscover_range,
        netdiscover_interface=netdiscover_interface,
        netdiscover_passive=netdiscover_passive,
        netdiscover_fast=netdiscover_fast,
        netdiscover_args=netdiscover_args,
        run_aircrack=aircrack,
        aircrack_interface=aircrack_interface,
        aircrack_channel=aircrack_channel,
        aircrack_args=aircrack_args,
        aircrack_airmon=aircrack_airmon,
        remediate=remediate,
        use_llm=not no_llm,
        max_remediations=max_remediations,
        min_remediation_severity=min_remediation_severity,
        progress_cb=progress_cb,
    )
    if agentic:
        run_kwargs["llm_plan"] = bool(llm_plan)
        run_kwargs["max_actions"] = int(max_actions)

    with console.status("[bold green]Running AI audit steps...[/bold green]" if agentic else "[bold green]Running audit steps...[/bold green]"):
        report = orchestrator.run(target, out_path, **run_kwargs)

    saved_path = report.get("saved_to")
    run_error = report.get("run_error")
    if saved_path:
        if agentic and run_error:
            console.print(f"[bold red]AI Audit FAILED.[/bold red] Report saved to [cyan]{saved_path}[/cyan]")
        elif agentic:
            console.print(f"[bold green]AI Audit complete.[/bold green] Report saved to [cyan]{saved_path}[/cyan]")
        else:
            console.print(f"[bold green]Audit complete.[/bold green] Report saved to [cyan]{saved_path}[/cyan]")
    else:
        console.print("[yellow]Audit completed but failed to write report file.[/yellow]")
        if "write_error" in report:
            console.print(f"[red]{report['write_error']}[/red]")
        if run_error:
            console.print(f"[red]{run_error}[/red]")

    if saved_path:
        try:
            from supabash.report import write_markdown
            from supabash.report_export import export_from_markdown_file
            md_written = write_markdown(report, md_path)
            console.print(f"[green]Markdown report written to {md_written}[/green]")
            exports = export_from_markdown_file(Path(md_written), config=config_manager.config)
            if exports.html_path:
                console.print(f"[green]HTML report written to {exports.html_path}[/green]")
            if exports.pdf_path:
                console.print(f"[green]PDF report written to {exports.pdf_path}[/green]")
            if exports.html_error:
                console.print(f"[yellow]HTML export skipped:[/yellow] {exports.html_error}")
            if exports.pdf_error:
                console.print(f"[yellow]PDF export skipped:[/yellow] {exports.pdf_error}")
        except Exception as e:
            console.print(f"[yellow]Failed to write Markdown report:[/yellow] {e}")

    if agentic and run_error:
        raise typer.Exit(code=1)


@app.command("ai-audit")
def ai_audit(
    target: str = typer.Argument(..., help="Target IP, URL, or Container ID"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Output JSON path (default: reports/ai-audit(-<profile>)-YYYYmmdd-HHMMSS/ai-audit(-<profile>)-YYYYmmdd-HHMMSS.json)"
        ),
    ),
    container_image: str = typer.Option(None, "--container-image", "-c", help="Optional container image to scan with Trivy"),
    markdown: Optional[str] = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Output Markdown path (default: derived from --output with .md)",
    ),
    status: bool = typer.Option(True, "--status/--no-status", help="Print live progress updates during the run"),
    status_file: Optional[str] = typer.Option(None, "--status-file", help="Write JSON status updates to this file while running"),
    allow_unsafe: bool = typer.Option(False, "--force", help="Bypass allowed-hosts safety check"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public IP targets (requires authorization)"),
    consent: bool = typer.Option(False, "--yes", help="Skip consent prompt"),
    mode: str = typer.Option("normal", "--mode", help="Scan mode: normal|stealth|aggressive"),
    compliance: Optional[str] = typer.Option(
        None,
        "--compliance",
        help="Compliance profile for audit planning (pci, soc2, iso, dora, nis2, gdpr, bsi)",
    ),
    nuclei_rate_limit: int = typer.Option(0, "--nuclei-rate", help="Nuclei request rate limit (per second)"),
    nuclei_tags: str = typer.Option(None, "--nuclei-tags", help="Comma-separated Nuclei template tags"),
    nuclei_severity: str = typer.Option(None, "--nuclei-severity", help="Comma-separated Nuclei severities (e.g. low,medium,high)"),
    gobuster_threads: int = typer.Option(10, "--gobuster-threads", help="Gobuster thread count"),
    gobuster_wordlist: str = typer.Option(None, "--gobuster-wordlist", help="Gobuster wordlist path"),
    parallel_web: bool = typer.Option(False, "--parallel-web", help="Run web tools in parallel (URL targets can overlap with recon)"),
    max_workers: int = typer.Option(3, "--max-workers", help="Max concurrent workers when --parallel-web is enabled"),
    nikto: bool = typer.Option(False, "--nikto", help="Run Nikto web scan (slow; opt-in)"),
    hydra: bool = typer.Option(False, "--hydra", help="Run Hydra bruteforce (opt-in; requires explicit wordlists)"),
    hydra_usernames: Optional[str] = typer.Option(None, "--hydra-usernames", help="Hydra usernames (path to file or single username)"),
    hydra_passwords: Optional[str] = typer.Option(None, "--hydra-passwords", help="Hydra passwords (path to file or single password)"),
    hydra_services: str = typer.Option("ssh,ftp", "--hydra-services", help="Comma-separated hydra services (e.g. ssh,ftp)"),
    hydra_threads: int = typer.Option(4, "--hydra-threads", help="Hydra parallel tasks (-t)"),
    hydra_options: Optional[str] = typer.Option(None, "--hydra-options", help="Extra Hydra CLI options (advanced)"),
    medusa: bool = typer.Option(False, "--medusa", help="Run Medusa bruteforce (opt-in; requires explicit wordlists)"),
    medusa_usernames: Optional[str] = typer.Option(None, "--medusa-usernames", help="Medusa usernames (path to file or single username)"),
    medusa_passwords: Optional[str] = typer.Option(None, "--medusa-passwords", help="Medusa passwords (path to file or single password)"),
    medusa_module: Optional[str] = typer.Option(None, "--medusa-module", help="Medusa module/service (default: derived from nmap)"),
    medusa_port: Optional[int] = typer.Option(None, "--medusa-port", help="Medusa target port (default: derived from nmap)"),
    medusa_threads: int = typer.Option(4, "--medusa-threads", help="Medusa parallel threads (-t)"),
    medusa_timeout: int = typer.Option(10, "--medusa-timeout", help="Medusa timeout per connection (seconds)"),
    medusa_options: Optional[str] = typer.Option(None, "--medusa-options", help="Extra Medusa CLI options (advanced)"),
    crackmapexec: bool = typer.Option(False, "--crackmapexec", "--cme", help="Run CrackMapExec/NetExec (opt-in)"),
    cme_protocol: str = typer.Option("smb", "--cme-protocol", help="CME protocol (smb, ssh, ldap, winrm, mssql, rdp)"),
    cme_username: Optional[str] = typer.Option(None, "--cme-username", help="CME username"),
    cme_password: Optional[str] = typer.Option(None, "--cme-password", help="CME password"),
    cme_domain: Optional[str] = typer.Option(None, "--cme-domain", help="CME domain"),
    cme_hashes: Optional[str] = typer.Option(None, "--cme-hashes", help="CME NTLM hashes (LM:NT or NT)"),
    cme_module: Optional[str] = typer.Option(None, "--cme-module", help="CME module to run"),
    cme_module_options: Optional[str] = typer.Option(None, "--cme-module-options", help="CME module options"),
    cme_enum: Optional[str] = typer.Option(None, "--cme-enum", help="CME enumeration flags (comma-separated; e.g. shares,users)"),
    cme_args: Optional[str] = typer.Option(None, "--cme-args", help="Extra CME CLI arguments (allows anonymous runs)"),
    scoutsuite: bool = typer.Option(False, "--scoutsuite", help="Run ScoutSuite (multi-cloud; opt-in)"),
    scoutsuite_provider: str = typer.Option("aws", "--scoutsuite-provider", help="ScoutSuite provider (aws, azure, gcp)"),
    scoutsuite_args: Optional[str] = typer.Option(None, "--scoutsuite-args", help="Extra ScoutSuite CLI arguments"),
    prowler: bool = typer.Option(False, "--prowler", help="Run Prowler (AWS; opt-in)"),
    prowler_args: Optional[str] = typer.Option(None, "--prowler-args", help="Extra Prowler CLI arguments"),
    theharvester: bool = typer.Option(False, "--theharvester", help="Run theHarvester OSINT (domain targets only; opt-in)"),
    theharvester_sources: Optional[str] = typer.Option(None, "--theharvester-sources", help="theHarvester data sources (comma-separated)"),
    theharvester_limit: Optional[int] = typer.Option(None, "--theharvester-limit", help="theHarvester results per source (default 500)"),
    theharvester_start: Optional[int] = typer.Option(None, "--theharvester-start", help="theHarvester start index (default 0)"),
    theharvester_args: Optional[str] = typer.Option(None, "--theharvester-args", help="Extra theHarvester CLI args"),
    netdiscover: bool = typer.Option(False, "--netdiscover", help="Run netdiscover LAN discovery (opt-in)"),
    netdiscover_range: Optional[str] = typer.Option(None, "--netdiscover-range", help="Netdiscover CIDR range (e.g. 192.168.1.0/24)"),
    netdiscover_interface: Optional[str] = typer.Option(None, "--netdiscover-interface", help="Netdiscover interface (e.g. eth0)"),
    netdiscover_passive: bool = typer.Option(False, "--netdiscover-passive", help="Netdiscover passive mode (sniff only)"),
    netdiscover_fast: bool = typer.Option(True, "--netdiscover-fast/--netdiscover-no-fast", help="Netdiscover fast mode"),
    netdiscover_args: Optional[str] = typer.Option(None, "--netdiscover-args", help="Extra netdiscover CLI args"),
    aircrack: bool = typer.Option(False, "--aircrack", "--aircrack-ng", help="Run Aircrack-ng suite (WiFi; opt-in)"),
    aircrack_interface: Optional[str] = typer.Option(None, "--aircrack-interface", help="Wireless interface for airodump-ng (e.g. wlan0mon)"),
    aircrack_channel: Optional[str] = typer.Option(None, "--aircrack-channel", help="WiFi channel to lock during capture"),
    aircrack_args: Optional[str] = typer.Option(None, "--aircrack-args", help="Extra airodump-ng CLI args"),
    aircrack_airmon: bool = typer.Option(False, "--aircrack-airmon", help="Auto start/stop monitor mode with airmon-ng"),
    llm_plan: bool = typer.Option(
        True,
        "--llm-plan/--no-llm-plan",
        help="Use tool-calling LLM planning for agentic expansion (requires LLM enabled)",
    ),
    max_actions: int = typer.Option(10, "--max-actions", help="Maximum agentic expansion actions"),
    remediate: bool = typer.Option(False, "--remediate", help="Use the LLM to generate concrete remediation steps + code snippets"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable LLM summary/remediation for this run (offline/no-LLM mode)"),
    max_remediations: int = typer.Option(5, "--max-remediations", help="Maximum findings to remediate (cost control)"),
    min_remediation_severity: str = typer.Option("MEDIUM", "--min-remediation-severity", help="Only remediate findings at or above this severity"),
):
    """
    Agentic audit: baseline audit pipeline + optional tool-calling expansion.

    Alias for: `supabash audit --agentic ...`
    """
    return audit(
        target=target,
        output=output,
        container_image=container_image,
        markdown=markdown,
        status=status,
        status_file=status_file,
        allow_unsafe=allow_unsafe,
        allow_public=allow_public,
        consent=consent,
        mode=mode,
        compliance=compliance,
        nuclei_rate_limit=nuclei_rate_limit,
        nuclei_tags=nuclei_tags,
        nuclei_severity=nuclei_severity,
        gobuster_threads=gobuster_threads,
        gobuster_wordlist=gobuster_wordlist,
        parallel_web=parallel_web,
        max_workers=max_workers,
        nikto=nikto,
        hydra=hydra,
        hydra_usernames=hydra_usernames,
        hydra_passwords=hydra_passwords,
        hydra_services=hydra_services,
        hydra_threads=hydra_threads,
        hydra_options=hydra_options,
        medusa=medusa,
        medusa_usernames=medusa_usernames,
        medusa_passwords=medusa_passwords,
        medusa_module=medusa_module,
        medusa_port=medusa_port,
        medusa_threads=medusa_threads,
        medusa_timeout=medusa_timeout,
        medusa_options=medusa_options,
        crackmapexec=crackmapexec,
        cme_protocol=cme_protocol,
        cme_username=cme_username,
        cme_password=cme_password,
        cme_domain=cme_domain,
        cme_hashes=cme_hashes,
        cme_module=cme_module,
        cme_module_options=cme_module_options,
        cme_enum=cme_enum,
        cme_args=cme_args,
        scoutsuite=scoutsuite,
        scoutsuite_provider=scoutsuite_provider,
        scoutsuite_args=scoutsuite_args,
        prowler=prowler,
        prowler_args=prowler_args,
        theharvester=theharvester,
        theharvester_sources=theharvester_sources,
        theharvester_limit=theharvester_limit,
        theharvester_start=theharvester_start,
        theharvester_args=theharvester_args,
        netdiscover=netdiscover,
        netdiscover_range=netdiscover_range,
        netdiscover_interface=netdiscover_interface,
        netdiscover_passive=netdiscover_passive,
        netdiscover_fast=netdiscover_fast,
        netdiscover_args=netdiscover_args,
        aircrack=aircrack,
        aircrack_interface=aircrack_interface,
        aircrack_channel=aircrack_channel,
        aircrack_args=aircrack_args,
        aircrack_airmon=aircrack_airmon,
        agentic=True,
        llm_plan=llm_plan,
        max_actions=max_actions,
        remediate=remediate,
        no_llm=no_llm,
        max_remediations=max_remediations,
        min_remediation_severity=min_remediation_severity,
    )

@app.command()
def config(
    provider: str = typer.Option(None, "--provider", "-p", help="Set active LLM provider (openai, anthropic, gemini, ollama, lmstudio, or custom)"),
    key: str = typer.Option(None, "--key", "-k", help="Set API Key for the selected/active provider"),
    model: str = typer.Option(None, "--model", "-m", help="Set Model name for the selected/active provider"),
    api_base: str = typer.Option(None, "--api-base", help="Set API base URL for the selected/active provider"),
    allow_host: str = typer.Option(None, "--allow-host", help="Add an allowed host/IP/CIDR entry"),
    remove_host: str = typer.Option(None, "--remove-host", help="Remove an allowed host/IP/CIDR entry"),
    list_allowed_hosts: bool = typer.Option(False, "--list-allowed-hosts", help="List allowed hosts"),
    accept_consent: bool = typer.Option(False, "--accept-consent", help="Persist consent_accepted=true"),
    reset_consent: bool = typer.Option(False, "--reset-consent", help="Set consent_accepted=false"),
    allow_public_ips: Optional[bool] = typer.Option(
        None,
        "--allow-public-ips/--no-allow-public-ips",
        help="Allow scanning public IP targets (still requires authorization)",
    ),
):
    """
    View or update configuration settings.
    """
    logger.info("Command 'config' triggered")
    console.print(Panel("[bold green]Configuration Manager[/bold green]", expand=False))
    
    # 1. Handle Flags (Non-Interactive Mode)
    if provider or key or model or api_base or allow_host or remove_host or list_allowed_hosts or accept_consent or reset_consent or allow_public_ips is not None:
        any_changes = False

        if list_allowed_hosts:
            allowed_hosts = config_manager.get_allowed_hosts()
            console.print("[bold]Allowed Hosts:[/bold]")
            for h in allowed_hosts:
                console.print(f"- {h}")

        if allow_host:
            config_manager.add_allowed_host(allow_host)
            console.print(f"Added allowed host: [cyan]{allow_host}[/cyan]")
            any_changes = True

        if remove_host:
            config_manager.remove_allowed_host(remove_host)
            console.print(f"Removed allowed host: [cyan]{remove_host}[/cyan]")
            any_changes = True

        if accept_consent:
            config_manager.set_consent_accepted(True)
            console.print("[green]Consent persisted (consent_accepted=true).[/green]")
            any_changes = True

        if reset_consent:
            config_manager.set_consent_accepted(False)
            console.print("[yellow]Consent reset (consent_accepted=false).[/yellow]")
            any_changes = True

        if allow_public_ips is not None:
            config_manager.set_allow_public_ips(allow_public_ips)
            state = "enabled" if allow_public_ips else "disabled"
            console.print(f"[yellow]Public IP scanning {state}[/yellow] (core.allow_public_ips={bool(allow_public_ips)})")
            any_changes = True

        if provider or key or model or api_base:
            current_llm = config_manager.get_llm_config()
            # Determine which provider we are editing (defaults to active if not specified)
            target_provider = provider if provider else current_llm["provider"]
            
            if target_provider not in ["openai", "anthropic", "gemini", "ollama", "lmstudio"]:
                console.print(f"[yellow]Warning: '{target_provider}' is not a standard provider.[/yellow]")

            if provider:
                config_manager.set_active_provider(provider)
                console.print(f"Active provider set to: [cyan]{provider}[/cyan]")
                any_changes = True
            
            if key:
                config_manager.set_llm_key(target_provider, key)
                console.print(f"API Key updated for: [cyan]{target_provider}[/cyan]")
                any_changes = True
                
            if model:
                config_manager.set_model(target_provider, model)
                console.print(f"Model updated for [cyan]{target_provider}[/cyan] to: [green]{model}[/green]")
                any_changes = True

            if api_base is not None:
                config_manager.set_api_base(target_provider, api_base)
                shown = api_base if api_base else "(cleared)"
                console.print(f"API base updated for [cyan]{target_provider}[/cyan] to: [green]{shown}[/green]")
                any_changes = True
            
        if any_changes:
            console.print(f"[bold green]Configuration saved to {config_manager.config_file}[/bold green]")
        return

    # 2. Interactive Mode (Default)
    llm_config = config_manager.config.get("llm", {})
    current_provider = llm_config.get("provider", "openai")
    
    available_providers = [k for k, v in llm_config.items() if k != "provider" and isinstance(v, dict)]
    
    console.print(f"Current Active Provider: [bold cyan]{current_provider.upper()}[/bold cyan]")
    console.print(f"Config File: [dim]{config_manager.config_file}[/dim]")
    console.print(f"Public IP scanning: [bold]{'enabled' if config_manager.get_allow_public_ips() else 'disabled'}[/bold]")
    console.print("\n[bold]Available Providers:[/bold]")
    
    if not available_providers:
        console.print("[yellow]No providers configured yet. Add one to get started.[/yellow]")
    else:
        for i, prov in enumerate(available_providers, 1):
            is_active = " (Active)" if prov == current_provider else ""
            details = llm_config[prov]
            model_name = details.get("model", "unknown")
            key_val = details.get("api_key")
            if prov in ("ollama", "lmstudio"):
                key_status = "N/A"
            else:
                key_ok = bool(key_val) and str(key_val).strip() not in ("YOUR_KEY_HERE", "None", "none", "null")
                key_status = "OK" if key_ok else "MISSING"
            
            console.print(f"{i}. [green]{prov}[/green] [dim]({model_name})[/dim] - Key: {key_status}{is_active}")

    console.print(f"\n[bold]Options:[/bold]")
    console.print("1. Switch/Edit existing provider")
    console.print("2. [bold yellow]Add New Custom Provider[/bold yellow]")
    console.print("3. Exit")

    option = typer.prompt("Select an option by number")

    if option == "3":
        return

    if option == "2":
        # Create New Provider Flow
        new_name = typer.prompt("Enter name for new provider (e.g. 'local-mistral', 'azure-gpt')").lower()
        if new_name in available_providers:
            console.print(f"[red]Error: Provider '{new_name}' already exists. Use edit mode.[/red]")
            return
            
        new_key = typer.prompt("Enter API Key (press Enter for none/local)", default="", hide_input=True)
        new_model = typer.prompt("Enter Model Name (e.g. 'mistral', 'gpt-4')")
        new_base = typer.prompt("Enter API Base URL (Optional, press Enter to skip)", default="")
        
        # Save new provider
        config_manager.config["llm"][new_name] = {
            "api_key": new_key,
            "model": new_model
        }
        if new_base:
            config_manager.config["llm"][new_name]["api_base"] = new_base
            
        config_manager.set_active_provider(new_name)
        console.print(f"[bold green]Successfully added and switched to custom provider '{new_name}'![/bold green]")
        return

    # Option 1: Switch/Edit Logic
    if not available_providers:
        console.print("[red]No providers to switch/edit. Add a provider first.[/red]")
        return

    example_name = available_providers[0]
    choice = typer.prompt(f"Enter provider name to switch/edit (e.g. {example_name})")
    
    if choice not in available_providers:
        console.print(f"[red]Provider '{choice}' not found.[/red]")
        return
        
    config_manager.set_active_provider(choice)
    current_provider = choice
        
    console.print(f"[green]Active provider is now: {current_provider}[/green]")
    
    # Ask to update key/model
    if typer.confirm(f"Do you want to edit settings for {current_provider}?"):
        current_data = llm_config.get(current_provider, {})
        new_key = typer.prompt("API Key", default=current_data.get("api_key", ""), hide_input=True)
        new_model = typer.prompt("Model Name", default=current_data.get("model", ""))
        new_base = typer.prompt("API Base URL (Optional)", default=current_data.get("api_base", ""))
        
        config_manager.set_llm_key(current_provider, new_key)
        config_manager.set_model(current_provider, new_model)
        if new_base:
             config_manager.config["llm"][current_provider]["api_base"] = new_base
             config_manager.save_config(config_manager.config)
             
        console.print("[bold green]Settings updated![/bold green]")

@app.command()
def chat():
    """
    Enter interactive chat mode with the Security Agent.
    """
    logger.info("Command 'chat' triggered")
    console.print("[bold magenta][*] Interactive Chat Mode[/bold magenta]")
    console.print(
        "[dim]Type 'exit' to quit. Use slash commands:\n"
        "/scan, /audit, /ai-audit, /status, /stop, /details [tool], /report, /test, /summary, /fix, /plan, /clear-state[/dim]"
    )
    allowed = config_manager.config.get("core", {}).get("allowed_hosts", [])
    session = ChatSession(allowed_hosts=allowed, config_manager=config_manager)
    state_path = default_chat_state_path()
    loaded = session.load_state(state_path)
    if loaded.get("success"):
        console.print(f"[dim]Resumed last session state from {loaded.get('path')}[/dim]")
        try:
            if getattr(session, "conversation_summary", ""):
                console.print("[dim]Conversation memory summary loaded.[/dim]")
        except Exception:
            pass

    def show_llm_usage(meta: dict):
        if not isinstance(meta, dict):
            return
        parts = []
        usage = meta.get("usage")
        if isinstance(usage, dict):
            total = usage.get("total_tokens")
            prompt = usage.get("prompt_tokens")
            completion = usage.get("completion_tokens")
            if total is not None:
                parts.append(f"tokens={total}")
            if prompt is not None and completion is not None:
                parts.append(f"prompt={prompt} completion={completion}")
        cost = meta.get("cost_usd")
        if cost is not None:
            parts.append(f"cost_usd={cost:.6f}" if isinstance(cost, (int, float)) else f"cost_usd={cost}")
        est = meta.get("estimated_prompt_tokens")
        max_in = meta.get("max_input_tokens")
        pct = meta.get("context_usage_pct")
        if est is not None:
            if max_in is not None and pct is not None:
                parts.append(f"context≈{est}/{max_in} ({pct}%)")
            elif max_in is not None:
                parts.append(f"context≈{est}/{max_in}")
            else:
                parts.append(f"context≈{est} tokens")
        if parts:
            console.print(f"[dim]LLM usage: {' | '.join(parts)}[/dim]")

    def show_scan(result):
        if not result.get("success"):
            console.print(f"[red]Scan failed:[/red] {result.get('error','')}")
            return
        data = result.get("scan_data", {})
        hosts = data.get("hosts", [])
        if not hosts:
            console.print("[yellow]No hosts found.[/yellow]")
            return
        for host in hosts:
            ip = host.get("ip", "unknown")
            hostnames = ", ".join(host.get("hostnames", []))
            os_matches = host.get("os", [])
            os_name = os_matches[0]["name"] if os_matches else "Unknown"
            console.print(Panel(f"[bold]Target:[/bold] {ip} ({hostnames})\n[bold]OS:[/bold] {os_name}", title="Scan Results", border_style="green"))
            ports_list = host.get("ports", [])
            if ports_list:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Port")
                table.add_column("State")
                table.add_column("Service")
                table.add_column("Info")
                for p in ports_list:
                    details = " ".join(filter(None, [p.get("product",""), p.get("version",""), p.get("protocol","")])).strip()
                    table.add_row(str(p.get("port","")), p.get("state",""), p.get("service",""), details)
                console.print(table)

    def show_audit(report: dict):
        if not isinstance(report, dict):
            console.print("[red]Audit failed.[/red]")
            return
        if report.get("error") and not report.get("target"):
            console.print(f"[red]Audit failed:[/red] {report.get('error','')}")
            return
        target = report.get("target", "unknown")
        findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []
        high = sum(1 for f in findings if str(f.get("severity", "")).upper() in ("HIGH", "CRITICAL"))
        med = sum(1 for f in findings if str(f.get("severity", "")).upper() == "MEDIUM")
        low = sum(1 for f in findings if str(f.get("severity", "")).upper() == "LOW")
        info = sum(1 for f in findings if str(f.get("severity", "")).upper() == "INFO")
        console.print(
            Panel(
                f"[bold]Target:[/bold] {target}\n[bold]Findings:[/bold] HIGH/CRIT={high}  MED={med}  LOW={low}  INFO={info}",
                title="Audit Results",
                border_style="red",
            )
        )
        if report.get("saved_to"):
            console.print(f"[green]Saved JSON:[/green] {report.get('saved_to')}")
        replay = report.get("replay_trace")
        if isinstance(replay, dict):
            replay_file = replay.get("file")
            replay_md_file = replay.get("markdown_file")
            replay_steps = replay.get("step_count")
            replay_version = replay.get("version")
            parts = []
            if isinstance(replay_file, str) and replay_file.strip():
                parts.append(replay_file.strip())
            if isinstance(replay_md_file, str) and replay_md_file.strip():
                parts.append(replay_md_file.strip())
            if isinstance(replay_steps, int):
                parts.append(f"steps={replay_steps}")
            if isinstance(replay_version, int):
                parts.append(f"v{replay_version}")
            if parts:
                console.print(f"[cyan]Replay Trace:[/cyan] {' | '.join(parts)}")
        llm_trace = report.get("llm_reasoning_trace")
        if isinstance(llm_trace, dict):
            parts = []
            trace_json = llm_trace.get("json_file")
            trace_md = llm_trace.get("markdown_file")
            trace_steps = llm_trace.get("decision_steps")
            trace_events = llm_trace.get("event_count")
            if isinstance(trace_json, str) and trace_json.strip():
                parts.append(trace_json.strip())
            if isinstance(trace_md, str) and trace_md.strip():
                parts.append(trace_md.strip())
            if isinstance(trace_steps, int):
                parts.append(f"steps={trace_steps}")
            if isinstance(trace_events, int):
                parts.append(f"events={trace_events}")
            if parts:
                console.print(f"[cyan]LLM Trace:[/cyan] {' | '.join(parts)}")
        ai_meta = report.get("ai_audit")
        if isinstance(ai_meta, dict):
            trace = ai_meta.get("decision_trace")
            if isinstance(trace, list):
                console.print(f"[cyan]Agent Decisions:[/cyan] {len(trace)} step(s)")
        chat_meta = report.get("_chat", {}) if isinstance(report.get("_chat"), dict) else {}
        if chat_meta.get("markdown_saved_to"):
            console.print(f"[green]Saved Markdown:[/green] {chat_meta.get('markdown_saved_to')}")

    last_job_hint = {"job_id": None, "state": None, "step": None}

    while True:
        try:
            active = session.job_status()
        except Exception:
            active = None
        if active and getattr(active, "state", None) in ("queued", "running"):
            job_id = getattr(active, "job_id", None)
            step = getattr(active, "current_step", None)
            state = getattr(active, "state", None)
            if (
                last_job_hint.get("job_id") != job_id
                or last_job_hint.get("state") != state
                or last_job_hint.get("step") != step
            ):
                msg = getattr(active, "message", None) or ""
                step_txt = f" step={step}" if step else ""
                msg_txt = f" — {msg}" if msg else ""
                console.print(f"[dim]Job running: {active.kind} target={active.target} id={job_id} state={state}{step_txt}{msg_txt}[/dim]")
                console.print("[dim]Use /status (or /status --watch) for live progress, or /stop to cancel.[/dim]")
                last_job_hint.update({"job_id": job_id, "state": state, "step": step})

        user_input = typer.prompt("chat> ")
        if not user_input.strip():
            continue
        if user_input.strip().lower() in ("exit", "quit"):
            break
        # Record user message for chat memory.
        try:
            session.add_message("user", user_input)
        except Exception:
            pass

        # If a suggested command is pending, treat y/n as confirmation.
        try:
            pending = getattr(session, "pending_action", None)
        except Exception:
            pending = None
        if isinstance(pending, dict) and pending.get("command"):
            if user_input.strip().startswith("/"):
                # User chose to drive manually; drop any pending proposal.
                session.pending_action = None
            else:
                low = user_input.strip().lower()
                if low in ("y", "yes"):
                    cmd = str(pending.get("command"))
                    session.pending_action = None
                    console.print(f"[cyan]Running proposed command:[/cyan] {cmd}")
                    try:
                        session.add_message("assistant", f"Running proposed command: {cmd}")
                    except Exception:
                        pass
                    user_input = cmd
                elif low in ("n", "no"):
                    session.pending_action = None
                    console.print("[dim]Canceled proposed command.[/dim]")
                    try:
                        session.add_message("assistant", "Canceled proposed command.")
                    except Exception:
                        pass
                    session.save_state(state_path)
                    continue
                else:
                    # Safety: avoid executing a stale proposal later.
                    session.pending_action = None
        if user_input.startswith("/clear-state"):
            if clear_session_state(state_path):
                session.last_scan_result = None
                session.last_scan_tool = None
                session.last_audit_report = None
                session.last_result_kind = None
                session.last_llm_meta = None
                session.last_clarifier = None
                try:
                    session.messages = []
                    session.conversation_summary = ""
                    session.turns_since_summary = 0
                    session.pending_action = None
                except Exception:
                    pass
                console.print("[green]Cleared chat state.[/green]")
            else:
                console.print("[yellow]Failed to clear state.[/yellow]")
            continue
        if user_input.startswith("/status"):
            try:
                parts = shlex.split(user_input)
            except ValueError as e:
                console.print(f"[red]Parse error:[/red] {e}")
                continue
            watch = "--watch" in parts
            verbose = "--verbose" in parts
            interval = 1.0
            if "--interval" in parts:
                try:
                    idx = parts.index("--interval")
                    interval = float(parts[idx + 1])
                except Exception:
                    interval = 1.0
            interval = max(0.2, min(interval, 10.0))

            def render_once():
                done = session.finalize_job_if_done()
                status = session.job_status()
                if done and done.get("status") is not None:
                    status_obj = done["status"]
                    result = done.get("result")
                    console.print(f"[green]Job {status_obj.job_id} finished ({status_obj.state}) in {status_obj.elapsed_seconds():.1f}s[/green]")
                    if status_obj.kind == "scan" and isinstance(result, dict):
                        show_scan(result)
                    elif status_obj.kind == "audit" and isinstance(result, dict):
                        show_audit(result)
                    session.save_state(state_path)
                    return True
                if status:
                    console.print(
                        f"[cyan]Job {status.job_id} ({status.kind})[/cyan] target={status.target} "
                        f"state={status.state} elapsed={status.elapsed_seconds():.1f}s step={status.current_step or '-'}"
                    )
                    if status.message:
                        console.print(f"[dim]{status.message}[/dim]")
                    latest_decision = None
                    latest_critique = None
                    for ev in reversed(list(getattr(status, "events", []) or [])):
                        l = str(ev).lower()
                        if latest_decision is None and "llm_decision" in l:
                            latest_decision = str(ev)
                        if latest_critique is None and "llm_critique" in l:
                            latest_critique = str(ev)
                        if latest_decision and latest_critique:
                            break
                    if latest_decision:
                        console.print(f"[dim]Latest planner decision: {latest_decision}[/dim]")
                    if latest_critique:
                        console.print(f"[dim]Latest planner critique: {latest_critique}[/dim]")
                    if verbose and getattr(status, "events", None):
                        events = list(status.events)[-8:]
                        if events:
                            console.print("[dim]Recent:[/dim]")
                            for ev in events:
                                console.print(f"[dim]- {ev}[/dim]")
                else:
                    console.print("[dim]No active job.[/dim]")
                return False

            if watch:
                try:
                    while True:
                        finished = render_once()
                        if finished:
                            break
                        import time as _time
                        _time.sleep(interval)
                except KeyboardInterrupt:
                    console.print("[yellow]Stopped watching.[/yellow]")
            else:
                render_once()
            continue

        if user_input.startswith("/stop"):
            if session.stop_job():
                console.print("[yellow]Stop requested. Use /status to see when it stops.[/yellow]")
            else:
                console.print("[dim]No active job to stop.[/dim]")
            continue

        if user_input.startswith("/scan"):
            try:
                parts = shlex.split(user_input)
            except ValueError as e:
                console.print(f"[red]Parse error:[/red] {e}")
                continue
            target = None
            profile = "fast"
            scanner_name = "nmap"
            allow_public = False
            bg = False
            for i, token in enumerate(parts[1:], start=1):
                if token in ("--profile", "-p") and i + 1 < len(parts):
                    profile = parts[i + 1]
                elif token in ("--scanner", "-s") and i + 1 < len(parts):
                    scanner_name = parts[i + 1]
                elif token == "--allow-public":
                    allow_public = True
                elif token == "--bg":
                    bg = True
                elif not token.startswith("-") and target is None:
                    target = normalize_target_token(token)
            if not target:
                console.print("[red]Usage:[/red] /scan <target> [--profile fast|full|stealth] [--scanner nmap|masscan|rustscan] [--allow-public] [--bg]")
                continue
            if bg:
                try:
                    try:
                        session.add_tool_event(scanner_name, "job_start", f"profile={profile} target={target}")
                    except Exception:
                        pass
                    job = session.start_scan_job(target, profile=profile, scanner_name=scanner_name, allow_public=allow_public)
                    console.print(f"[cyan]Scan job started (id={job.job_id}). Use /status or /stop.[/cyan]")
                    try:
                        session.add_message(
                            "assistant",
                            f"Scan job started: scanner={scanner_name} profile={profile} target={target} (id={job.job_id})",
                        )
                    except Exception:
                        pass
                except Exception as e:
                    console.print(f"[red]Failed to start job:[/red] {e}")
            else:
                console.print(f"[cyan]Starting scan ({profile}) with {scanner_name} against {target}...[/cyan]")
                try:
                    session.add_tool_event(scanner_name, "start", f"profile={profile} target={target}")
                except Exception:
                    pass
                with console.status("[green]Running scan...[/green]"):
                    res = session.run_scan(target, profile=profile, scanner_name=scanner_name, allow_public=allow_public)
                show_scan(res)
                try:
                    if res.get("success"):
                        session.add_tool_event(scanner_name, "end", "success")
                    else:
                        session.add_tool_event(scanner_name, "end", f"failed: {res.get('error','')}")
                except Exception:
                    pass
                session.save_state(state_path)
            continue

        if user_input.startswith("/audit") or user_input.startswith("/ai-audit"):
            try:
                parts = shlex.split(user_input)
            except ValueError as e:
                console.print(f"[red]Parse error:[/red] {e}")
                continue

            invoked_ai_audit = str(parts[0] if parts else "").strip().lower() == "/ai-audit"
            target = None
            mode = "normal"
            # `/ai-audit` in chat is a convenience alias to `/audit --agentic`.
            agentic = bool(invoked_ai_audit)
            compliance = None
            llm_plan = True
            max_actions = 10
            no_llm = False
            nuclei_rate = 0
            gobuster_threads = 10
            gobuster_wordlist = None
            container_image = None
            markdown = None
            output = None
            remediate = False
            max_remediations = 5
            min_remediation_severity = "MEDIUM"
            allow_public = False
            parallel_web = False
            max_workers = 3
            bg = False
            run_nikto = False

            i = 1
            while i < len(parts):
                token = parts[i]
                if token == "--mode" and i + 1 < len(parts):
                    mode = parts[i + 1]
                    i += 2
                    continue
                if token == "--agentic":
                    agentic = True
                    i += 1
                    continue
                if token == "--compliance" and i + 1 < len(parts):
                    compliance = parts[i + 1]
                    i += 2
                    continue
                if token == "--llm-plan":
                    llm_plan = True
                    i += 1
                    continue
                if token == "--no-llm-plan":
                    llm_plan = False
                    i += 1
                    continue
                if token == "--max-actions" and i + 1 < len(parts):
                    max_actions = int(parts[i + 1])
                    i += 2
                    continue
                if token == "--no-llm":
                    no_llm = True
                    i += 1
                    continue
                if token == "--nuclei-rate" and i + 1 < len(parts):
                    nuclei_rate = int(parts[i + 1])
                    i += 2
                    continue
                if token == "--gobuster-threads" and i + 1 < len(parts):
                    gobuster_threads = int(parts[i + 1])
                    i += 2
                    continue
                if token == "--gobuster-wordlist" and i + 1 < len(parts):
                    gobuster_wordlist = parts[i + 1]
                    i += 2
                    continue
                if token == "--parallel-web":
                    parallel_web = True
                    i += 1
                    continue
                if token == "--max-workers" and i + 1 < len(parts):
                    max_workers = int(parts[i + 1])
                    i += 2
                    continue
                if token == "--container-image" and i + 1 < len(parts):
                    container_image = parts[i + 1]
                    i += 2
                    continue
                if token == "--nikto":
                    run_nikto = True
                    i += 1
                    continue
                if token == "--markdown" and i + 1 < len(parts):
                    markdown = parts[i + 1]
                    i += 2
                    continue
                if token == "--output" and i + 1 < len(parts):
                    output = parts[i + 1]
                    i += 2
                    continue
                if token == "--remediate":
                    remediate = True
                    i += 1
                    continue
                if token == "--max-remediations" and i + 1 < len(parts):
                    max_remediations = int(parts[i + 1])
                    i += 2
                    continue
                if token == "--min-remediation-severity" and i + 1 < len(parts):
                    min_remediation_severity = parts[i + 1]
                    i += 2
                    continue
                if token == "--allow-public":
                    allow_public = True
                    i += 1
                    continue
                if token == "--bg":
                    bg = True
                    i += 1
                    continue
                if not token.startswith("-") and target is None:
                    target = normalize_target_token(token)
                    i += 1
                    continue
                i += 1

            if not target:
                console.print(
                    "[red]Usage:[/red] /audit <target> [--mode normal|stealth|aggressive] "
                    "[--agentic] [--compliance PROFILE] [--llm-plan|--no-llm-plan] [--max-actions N] [--no-llm] "
                    "[--nuclei-rate N] [--gobuster-threads N] [--gobuster-wordlist PATH] "
                    "[--parallel-web] [--max-workers N] "
                    "[--container-image IMG] [--nikto] [--remediate] [--max-remediations N] [--min-remediation-severity SEV] "
                    "[--output reports/report-YYYYmmdd-HHMMSS/report-YYYYmmdd-HHMMSS.json] [--markdown reports/report-YYYYmmdd-HHMMSS/report-YYYYmmdd-HHMMSS.md] [--allow-public] [--bg]"
                )
                console.print("[dim]Alias:[/dim] /ai-audit <target> [same options]  (implies --agentic)")
                continue

            default_base = "ai-audit" if agentic and not output else "report"
            if agentic and not output and compliance:
                compliance_slug = _compliance_slug(compliance)
                if compliance_slug:
                    default_base = f"ai-audit-{compliance_slug}"
            out_path, md_path = build_report_paths(output, markdown, default_basename=default_base)
            formats_note = _report_formats_note(config_manager.config)
            console.print(f"[dim]Results will be saved to {out_path}{formats_note}[/dim]")

            if bg:
                try:
                    try:
                        session.add_tool_event(
                            "audit",
                            "job_start",
                            f"mode={mode} target={target} agentic={agentic} compliance={compliance or 'none'}",
                        )
                    except Exception:
                        pass
                    job = session.start_audit_job(
                        target,
                        agentic=agentic,
                        llm_plan=llm_plan,
                        max_actions=max_actions,
                        no_llm=no_llm,
                        compliance_profile=compliance,
                        mode=mode,
                        nuclei_rate_limit=nuclei_rate,
                        gobuster_threads=gobuster_threads,
                        gobuster_wordlist=gobuster_wordlist,
                        parallel_web=parallel_web,
                        max_workers=max_workers,
                        container_image=container_image,
                        run_nikto=run_nikto,
                        remediate=remediate,
                        max_remediations=max_remediations,
                        min_remediation_severity=min_remediation_severity,
                        allow_public=allow_public,
                        output=out_path,
                        markdown=md_path,
                    )
                    console.print(f"[cyan]Audit job started (id={job.job_id}). Use /status or /stop.[/cyan]")
                    try:
                        session.add_message(
                            "assistant",
                            f"Audit job started: mode={mode} target={target} agentic={agentic} compliance={compliance or 'none'} (id={job.job_id})",
                        )
                    except Exception:
                        pass
                except Exception as e:
                    console.print(f"[red]Failed to start job:[/red] {e}")
            else:
                label = "ai-audit" if agentic else "audit"
                console.print(f"[cyan]Starting {label} ({mode}) against {target}...[/cyan]")
                try:
                    session.add_tool_event(
                        "audit",
                        "start",
                        f"mode={mode} target={target} agentic={agentic} compliance={compliance or 'none'}",
                    )
                except Exception:
                    pass
                with console.status("[green]Running audit...[/green]"):
                    rep = session.run_audit(
                        target,
                        agentic=agentic,
                        llm_plan=llm_plan,
                        max_actions=max_actions,
                        no_llm=no_llm,
                        compliance_profile=compliance,
                        mode=mode,
                        nuclei_rate_limit=nuclei_rate,
                        gobuster_threads=gobuster_threads,
                        gobuster_wordlist=gobuster_wordlist,
                        parallel_web=parallel_web,
                        max_workers=max_workers,
                        container_image=container_image,
                        run_nikto=run_nikto,
                        remediate=remediate,
                        max_remediations=max_remediations,
                        min_remediation_severity=min_remediation_severity,
                        allow_public=allow_public,
                        output=out_path,
                        markdown=md_path,
                    )
                show_audit(rep)
                try:
                    if isinstance(rep, dict) and rep.get("error") and not rep.get("target"):
                        session.add_tool_event("audit", "end", f"failed: {rep.get('error','')}")
                    else:
                        session.add_tool_event("audit", "end", "success")
                except Exception:
                    pass
                session.save_state(state_path)
            continue

        if user_input.startswith("/details"):
            try:
                parts = shlex.split(user_input)
            except ValueError as e:
                console.print(f"[red]Parse error:[/red] {e}")
                continue
            tool = parts[1] if len(parts) > 1 else None
            if tool:
                entry = session.get_audit_tool_result(tool)
                if entry is None:
                    console.print(f"[yellow]No tool result found for '{tool}'.[/yellow]")
                else:
                    console.print(Panel(json.dumps(entry, indent=2)[:8000], title=f"Tool Details: {tool}", border_style="magenta"))
                continue

            if session.last_result_kind == "audit" and session.last_audit_report:
                console.print("[dim]Last result: audit[/dim]")
                show_audit(session.last_audit_report)
            elif session.last_scan_result:
                console.print(f"[dim]Last scan via {session.last_scan_tool}[/dim]")
                show_scan(session.last_scan_result)
            else:
                console.print("[yellow]No results yet.[/yellow]")
            continue

        if user_input.startswith("/summary"):
            with console.status("[green]Thinking...[/green]"):
                summary = session.summarize_findings()
            if summary:
                console.print(Panel(summary, title="LLM Summary", border_style="cyan"))
                try:
                    session.add_message("assistant", summary, meta={"source": "llm", "kind": "summary"})
                except Exception:
                    pass
                meta = getattr(session, "last_llm_meta", None) or {}
                show_llm_usage(meta if isinstance(meta, dict) else {})
                session.save_state(state_path)
            else:
                console.print("[yellow]No summary available (no data or LLM error).[/yellow]")
            continue

        if user_input.startswith("/fix"):
            parts = user_input.split(" ", 2)
            if len(parts) < 2:
                console.print("[red]Usage:[/red] /fix <title> [evidence]")
                continue
            title = parts[1]
            evidence = parts[2] if len(parts) > 2 else ""
            with console.status("[green]Thinking...[/green]"):
                resp = session.remediate(title=title, evidence=evidence)
            if resp:
                console.print(Panel(resp, title="LLM Fix", border_style="green"))
                try:
                    session.add_message("assistant", resp, meta={"source": "llm", "kind": "fix"})
                except Exception:
                    pass
                meta = getattr(session, "last_llm_meta", None) or {}
                show_llm_usage(meta if isinstance(meta, dict) else {})
                session.save_state(state_path)
            else:
                console.print("[yellow]No fix available (LLM error).[/yellow]")
            continue

        if user_input.startswith("/plan"):
            plan = session.plan_next()
            console.print(Panel(json.dumps(plan, indent=2), title="Next Steps", border_style="cyan"))
            continue

        if user_input.startswith("/report"):
            parts = shlex.split(user_input)
            if len(parts) > 1:
                path = Path(parts[1])
            else:
                ts = datetime.now().strftime("%Y%m%d-%H%M%S")
                path = Path("reports") / f"chat-{ts}.json"
            res = session.save_report(path)
            if res.get("success"):
                console.print(f"[green]Saved report to {res['path']}[/green]")
            else:
                console.print(f"[red]Failed to save report:[/red] {res.get('error','')}")
            continue

        if user_input.startswith("/test"):
            console.print("[cyan]Running unit tests...[/cyan]")
            with console.status("[green]Running tests...[/green]"):
                res = session.run_tests(workdir=Path(__file__).resolve().parents[2])
            if res.get("success"):
                console.print("[green]Tests passed[/green]")
            else:
                console.print(f"[red]Tests failed (rc={res.get('return_code')})[/red]")
            if res.get("stdout"):
                console.print(Panel(res["stdout"][-4000:], title="stdout", border_style="blue"))
            if res.get("stderr"):
                console.print(Panel(res["stderr"][-2000:], title="stderr", border_style="red"))
            continue

        # Freeform: ask clarifying questions + propose next commands (no auto-execution)
        with console.status("[green]Thinking...[/green]"):
            result = session.clarify_goal(user_input)
        questions = result.get("questions", [])
        suggested = result.get("suggested_commands", [])
        safety = result.get("safety", [])
        notes = result.get("notes", "")

        lines = []
        if questions:
            lines.append("[bold]Questions[/bold]")
            for q in questions[:8]:
                lines.append(f"- {q}")
        if suggested:
            lines.append("\n[bold]Suggested Commands[/bold]")
            for cmd in suggested[:8]:
                lines.append(f"- {cmd}")
        if safety:
            lines.append("\n[bold]Safety[/bold]")
            for s in safety[:6]:
                lines.append(f"- {s}")
        if notes:
            lines.append(f"\n[dim]{notes}[/dim]")

        if not lines:
            console.print(
                "[yellow]No suggestions available. Use slash commands: /scan, /audit, /ai-audit, /status, /stop, /details, /report, /test, /summary, /fix, /plan, /clear-state[/yellow]"
            )
            try:
                session.add_message(
                    "assistant",
                    "No suggestions available. Use slash commands: /scan, /audit, /ai-audit, /status, /stop, /details, /report, /test, /summary, /fix, /plan, /clear-state",
                    meta={"source": "llm", "kind": "planner"},
                )
            except Exception:
                pass
            session.save_state(state_path)
        else:
            console.print(Panel("\n".join(lines), title="Engagement Planner", border_style="cyan"))
            try:
                mem_lines = []
                if questions:
                    mem_lines.append("Questions:")
                    mem_lines.extend([f"- {q}" for q in questions[:8]])
                if suggested:
                    mem_lines.append("Suggested Commands:")
                    mem_lines.extend([f"- {c}" for c in suggested[:8]])
                if safety:
                    mem_lines.append("Safety:")
                    mem_lines.extend([f"- {s}" for s in safety[:6]])
                if notes:
                    mem_lines.append(f"Notes: {notes}")
                session.add_message("assistant", "\n".join(mem_lines), meta={"source": "llm", "kind": "planner"})
            except Exception:
                pass

            meta = getattr(session, "last_llm_meta", None) or {}
            show_llm_usage(meta if isinstance(meta, dict) else {})

            # Propose the first suggested command and require explicit confirmation.
            try:
                if suggested:
                    proposal = str(suggested[0]).strip()
                    if proposal:
                        session.pending_action = {"command": proposal, "ts": datetime.now().isoformat(timespec="seconds")}
                        console.print(f"[cyan]Proposed:[/cyan] {proposal}  [dim](run? y/N)[/dim]")
            except Exception:
                pass
            session.save_state(state_path)

@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    verbose: bool = typer.Option(False, "--verbose", help="Print extra details"),
):
    """
    Check environment readiness (config + system binaries).
    """
    from supabash.llm import LLMClient

    checks = []

    def add_check(name: str, ok: bool, message: str = "", *, required: bool = True, details: Optional[dict] = None):
        checks.append(
            {
                "name": name,
                "ok": bool(ok),
                "required": bool(required),
                "message": message,
                "details": details or {},
            }
        )

    # Python environment
    add_check(
        "python",
        True,
        f"{sys.version.split()[0]} ({sys.executable})",
        required=True,
        details={"executable": sys.executable, "version": sys.version.split()[0]},
    )
    add_check("venv", bool(os.getenv("VIRTUAL_ENV")), os.getenv("VIRTUAL_ENV", "not in venv"), required=False)

    # Python deps (best-effort)
    for mod in ("typer", "rich", "yaml", "litellm", "requests"):
        try:
            importlib.import_module(mod)
            add_check(f"py:{mod}", True, "installed", required=True)
        except Exception as e:
            add_check(f"py:{mod}", False, f"missing ({e})", required=True)

    # Config sanity (best-effort)
    cfg_path = getattr(config_manager, "config_file", None)
    cfg_ok = bool(cfg_path and Path(cfg_path).exists())
    add_check("config", cfg_ok, str(cfg_path) if cfg_path else "unknown", required=True)
    try:
        llm_client = LLMClient()
        provider = config_manager.config.get("llm", {}).get("provider")
        model = config_manager.config.get("llm", {}).get(provider, {}).get("model") if provider else None
        add_check("llm.provider", bool(provider), str(provider or "missing"), required=False)
        add_check("llm.model", bool(model), str(model or "missing"), required=False)
        # Don't fail doctor if key is missing; audit/summary will enforce at runtime.
        add_check("llm.key", True, "checked at runtime", required=False)
    except Exception as e:
        add_check("llm", False, f"error: {e}", required=False)

    # Reports directory
    reports_dir = Path("reports")
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        test_path = reports_dir / ".write_test"
        test_path.write_text("ok")
        test_path.unlink(missing_ok=True)
        add_check("reports_dir", True, str(reports_dir.resolve()), required=True)
    except Exception as e:
        add_check("reports_dir", False, f"not writable: {e}", required=True)

    # System binaries used by wrappers
    required_bins = [
        ("nmap", True),
        ("whatweb", True),
        ("nuclei", True),
        ("gobuster", True),
    ]
    optional_bins = [
        ("sqlmap", False),
        ("masscan", False),
        ("rustscan", False),
        ("subfinder", False),
        ("httpx", False),
        ("nikto", False),
        ("hydra", False),
        ("medusa", False),
        ("trivy", False),
        ("scout", False),
        ("prowler", False),
        ("sslscan", False),
        ("dnsenum", False),
        ("ffuf", False),
        ("katana", False),
        ("searchsploit", False),
        ("wpscan", False),
        ("netdiscover", False),
        ("airodump-ng", False),
        ("airmon-ng", False),
    ]

    for bin_name, req in required_bins + optional_bins:
        path = shutil.which(bin_name)
        add_check(f"bin:{bin_name}", bool(path), path or "missing", required=req, details={"which": path})

    # enum4linux / enum4linux-ng (either works)
    enum_legacy = shutil.which("enum4linux")
    enum_ng = shutil.which("enum4linux-ng")
    add_check(
        "bin:enum4linux",
        bool(enum_legacy or enum_ng),
        enum_legacy or enum_ng or "missing",
        required=False,
        details={"enum4linux": enum_legacy, "enum4linux-ng": enum_ng},
    )

    # theHarvester (case-sensitive, check both variants)
    theharvester_path = shutil.which("theHarvester") or shutil.which("theharvester")
    add_check(
        "bin:theHarvester",
        bool(theharvester_path),
        theharvester_path or "missing",
        required=False,
        details={"which": theharvester_path},
    )

    # CrackMapExec / NetExec (multiple possible binary names)
    cme_path = shutil.which("netexec") or shutil.which("nxc") or shutil.which("crackmapexec") or shutil.which("cme")
    add_check(
        "bin:crackmapexec",
        bool(cme_path),
        cme_path or "missing",
        required=False,
        details={"which": cme_path},
    )

    required_failed = [c for c in checks if c["required"] and not c["ok"]]
    overall_ok = not required_failed

    if json_output:
        import json

        console.print_json(json.dumps({"ok": overall_ok, "checks": checks}, indent=2))
        raise typer.Exit(code=0 if overall_ok else 1)

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Message")
    for c in checks:
        status = "[green]OK[/green]" if c["ok"] else ("[red]FAIL[/red]" if c["required"] else "[yellow]WARN[/yellow]")
        msg = c.get("message") or ""
        if verbose and c.get("details"):
            d = c["details"]
            if isinstance(d, dict) and d:
                msg = f"{msg} ({', '.join(f'{k}={v}' for k,v in list(d.items())[:3])})"
        table.add_row(c["name"], status, msg)
    console.print(table)
    if overall_ok:
        console.print("[green]Doctor: OK[/green]")
        raise typer.Exit(code=0)
    console.print("[red]Doctor: FAILED[/red] (missing required dependencies)")
    raise typer.Exit(code=1)

if __name__ == "__main__":
    # Intercept `supabash --help` to show an extended help view with per-command parameters.
    if _only_top_level_help_invocation(sys.argv):
        _print_extended_help()
        raise SystemExit(0)
    app()
