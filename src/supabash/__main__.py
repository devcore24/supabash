import typer
import shlex
from pathlib import Path
from typing import Optional
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
from supabash.audit import AuditOrchestrator
from supabash.session_state import default_chat_state_path, clear_state as clear_session_state
from supabash.react import ReActOrchestrator

app = typer.Typer(
    name="supabash",
    help="Supabash: The Autonomous AI Security Audit Agent",
    add_completion=False,
)
console = Console()
core_config = config_manager.config.get("core", {})
log_level = core_config.get("log_level", "INFO")
logger = setup_logger(log_level=log_level)

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

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Supabash Entry Point.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[bold green]Welcome to Supabash![/bold green]")
        console.print("Use [bold cyan]--help[/bold cyan] to see available commands.")

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
        if scanner_name == "nmap":
            result = scanner.scan(target, ports=ports, arguments=args)
        elif scanner_name == "masscan":
            result = scanner.scan(target, ports=ports, rate=extra_kwargs["rate"], arguments=args)
        else:
            result = scanner.scan(target, ports=ports, batch=extra_kwargs["batch"], arguments=args)

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
    output: str = typer.Option("report.json", "--output", "-o", help="Output file path"),
    container_image: str = typer.Option(None, "--container-image", "-c", help="Optional container image to scan with Trivy"),
    markdown: str = typer.Option(None, "--markdown", "-m", help="Optional markdown report path"),
    allow_unsafe: bool = typer.Option(False, "--force", help="Bypass allowed-hosts safety check"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public IP targets (requires authorization)"),
    consent: bool = typer.Option(False, "--yes", help="Skip consent prompt"),
    mode: str = typer.Option("normal", "--mode", help="Scan mode: normal|stealth|aggressive"),
    nuclei_rate_limit: int = typer.Option(0, "--nuclei-rate", help="Nuclei request rate limit (per second)"),
    gobuster_threads: int = typer.Option(10, "--gobuster-threads", help="Gobuster thread count"),
    gobuster_wordlist: str = typer.Option(None, "--gobuster-wordlist", help="Gobuster wordlist path"),
    parallel_web: bool = typer.Option(False, "--parallel-web", help="Run web tools in parallel (URL targets can overlap with recon)"),
    max_workers: int = typer.Option(3, "--max-workers", help="Max concurrent workers when --parallel-web is enabled"),
    remediate: bool = typer.Option(False, "--remediate", help="Use the LLM to generate concrete remediation steps + code snippets"),
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
    logger.info(f"Command 'audit' triggered for target: {target}")
    console.print(f"[bold red][*] initializing full audit protocol for {target}...[/bold red]")
    if container_image:
        console.print(f"[dim]Including container image: {container_image}[/dim]")
    console.print(f"[dim]Results will be saved to {output}[/dim]")

    orchestrator = AuditOrchestrator()
    with console.status("[bold green]Running audit steps...[/bold green]"):
        report = orchestrator.run(
            target,
            Path(output),
            container_image=container_image,
            mode=mode,
            nuclei_rate_limit=nuclei_rate_limit,
            gobuster_threads=gobuster_threads,
            gobuster_wordlist=gobuster_wordlist,
            parallel_web=parallel_web,
            max_workers=max_workers,
            remediate=remediate,
            max_remediations=max_remediations,
            min_remediation_severity=min_remediation_severity,
        )

    saved_path = report.get("saved_to")
    if saved_path:
        console.print(f"[bold green]Audit complete.[/bold green] Report saved to [cyan]{saved_path}[/cyan]")
    else:
        console.print("[yellow]Audit completed but failed to write report file.[/yellow]")
        if "write_error" in report:
            console.print(f"[red]{report['write_error']}[/red]")

    if markdown:
        from supabash.report import write_markdown
        md_path = write_markdown(report, Path(markdown))
        console.print(f"[green]Markdown report written to {md_path}[/green]")

@app.command()
def react(
    target: str = typer.Argument(..., help="Target IP or URL"),
    output: str = typer.Option("react_report.json", "--output", "-o", help="Output JSON report path"),
    markdown: str = typer.Option(None, "--markdown", "-m", help="Optional markdown report path"),
    allow_unsafe: bool = typer.Option(False, "--force", help="Bypass allowed-hosts safety check"),
    allow_public: bool = typer.Option(False, "--allow-public", help="Allow scanning public IP targets (requires authorization)"),
    consent: bool = typer.Option(False, "--yes", help="Skip consent prompt"),
    mode: str = typer.Option("normal", "--mode", help="Scan mode: normal|stealth|aggressive"),
    nuclei_rate_limit: int = typer.Option(0, "--nuclei-rate", help="Nuclei request rate limit (per second)"),
    gobuster_threads: int = typer.Option(10, "--gobuster-threads", help="Gobuster thread count"),
    gobuster_wordlist: str = typer.Option(None, "--gobuster-wordlist", help="Gobuster wordlist path"),
    remediate: bool = typer.Option(False, "--remediate", help="Use the LLM to generate remediation steps + code snippets"),
    max_remediations: int = typer.Option(5, "--max-remediations", help="Maximum findings to remediate (cost control)"),
    min_remediation_severity: str = typer.Option("MEDIUM", "--min-remediation-severity", help="Only remediate findings at or above this severity"),
    max_actions: int = typer.Option(10, "--max-actions", help="Maximum planned actions to execute in the loop"),
):
    """
    ReAct loop (plan → execute → summarize) driven by scan results.
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

    console.print(f"[bold red][*] Starting ReAct loop for {target}...[/bold red]")
    orchestrator = ReActOrchestrator()
    with console.status("[bold green]Running ReAct loop...[/bold green]"):
        report = orchestrator.run(
            target,
            Path(output) if output else None,
            mode=mode,
            nuclei_rate_limit=nuclei_rate_limit,
            gobuster_threads=gobuster_threads,
            gobuster_wordlist=gobuster_wordlist,
            remediate=remediate,
            max_remediations=max_remediations,
            min_remediation_severity=min_remediation_severity,
            max_actions=max_actions,
        )

    saved_path = report.get("saved_to")
    if saved_path:
        console.print(f"[bold green]ReAct complete.[/bold green] Report saved to [cyan]{saved_path}[/cyan]")
    else:
        console.print("[yellow]ReAct completed but did not write a report file.[/yellow]")
        if "write_error" in report:
            console.print(f"[red]{report['write_error']}[/red]")

    if markdown:
        from supabash.report import write_markdown
        md_path = write_markdown(report, Path(markdown))
        console.print(f"[green]Markdown report written to {md_path}[/green]")

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
    console.print("[dim]Type 'exit' to quit. Use slash commands: /scan, /audit, /status, /stop, /details [tool], /report, /test, /summary, /fix, /plan, /clear-state[/dim]")
    allowed = config_manager.config.get("core", {}).get("allowed_hosts", [])
    session = ChatSession(allowed_hosts=allowed, config_manager=config_manager)
    state_path = default_chat_state_path()
    loaded = session.load_state(state_path)
    if loaded.get("success"):
        console.print(f"[dim]Resumed last session state from {loaded.get('path')}[/dim]")

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
        chat_meta = report.get("_chat", {}) if isinstance(report.get("_chat"), dict) else {}
        if chat_meta.get("markdown_saved_to"):
            console.print(f"[green]Saved Markdown:[/green] {chat_meta.get('markdown_saved_to')}")

    while True:
        user_input = typer.prompt("chat> ")
        if not user_input.strip():
            continue
        if user_input.strip().lower() in ("exit", "quit"):
            break
        if user_input.startswith("/clear-state"):
            if clear_session_state(state_path):
                session.last_scan_result = None
                session.last_scan_tool = None
                session.last_audit_report = None
                session.last_result_kind = None
                session.last_llm_meta = None
                session.last_clarifier = None
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
                    target = token
            if not target:
                console.print("[red]Usage:[/red] /scan <target> [--profile fast|full|stealth] [--scanner nmap|masscan|rustscan] [--allow-public] [--bg]")
                continue
            if bg:
                try:
                    job = session.start_scan_job(target, profile=profile, scanner_name=scanner_name, allow_public=allow_public)
                    console.print(f"[cyan]Scan job started (id={job.job_id}). Use /status or /stop.[/cyan]")
                except Exception as e:
                    console.print(f"[red]Failed to start job:[/red] {e}")
            else:
                console.print(f"[cyan]Starting scan ({profile}) with {scanner_name} against {target}...[/cyan]")
                with console.status("[green]Running scan...[/green]"):
                    res = session.run_scan(target, profile=profile, scanner_name=scanner_name, allow_public=allow_public)
                show_scan(res)
                session.save_state(state_path)
            continue

        if user_input.startswith("/audit"):
            try:
                parts = shlex.split(user_input)
            except ValueError as e:
                console.print(f"[red]Parse error:[/red] {e}")
                continue

            target = None
            mode = "normal"
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

            i = 1
            while i < len(parts):
                token = parts[i]
                if token == "--mode" and i + 1 < len(parts):
                    mode = parts[i + 1]
                    i += 2
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
                    target = token
                    i += 1
                    continue
                i += 1

            if not target:
                console.print(
                    "[red]Usage:[/red] /audit <target> [--mode normal|stealth|aggressive] "
                    "[--nuclei-rate N] [--gobuster-threads N] [--gobuster-wordlist PATH] "
                    "[--parallel-web] [--max-workers N] "
                    "[--container-image IMG] [--remediate] [--max-remediations N] [--min-remediation-severity SEV] "
                    "[--output report.json] [--markdown report.md] [--allow-public] [--bg]"
                )
                continue

            if bg:
                try:
                    job = session.start_audit_job(
                        target,
                        mode=mode,
                        nuclei_rate_limit=nuclei_rate,
                        gobuster_threads=gobuster_threads,
                        gobuster_wordlist=gobuster_wordlist,
                        parallel_web=parallel_web,
                        max_workers=max_workers,
                        container_image=container_image,
                        remediate=remediate,
                        max_remediations=max_remediations,
                        min_remediation_severity=min_remediation_severity,
                        allow_public=allow_public,
                        output=Path(output) if output else None,
                        markdown=Path(markdown) if markdown else None,
                    )
                    console.print(f"[cyan]Audit job started (id={job.job_id}). Use /status or /stop.[/cyan]")
                except Exception as e:
                    console.print(f"[red]Failed to start job:[/red] {e}")
            else:
                console.print(f"[cyan]Starting audit ({mode}) against {target}...[/cyan]")
                with console.status("[green]Running audit...[/green]"):
                    rep = session.run_audit(
                        target,
                        mode=mode,
                        nuclei_rate_limit=nuclei_rate,
                        gobuster_threads=gobuster_threads,
                        gobuster_wordlist=gobuster_wordlist,
                        parallel_web=parallel_web,
                        max_workers=max_workers,
                        container_image=container_image,
                        remediate=remediate,
                        max_remediations=max_remediations,
                        min_remediation_severity=min_remediation_severity,
                        allow_public=allow_public,
                        output=Path(output) if output else None,
                        markdown=Path(markdown) if markdown else None,
                    )
                show_audit(rep)
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
            summary = session.summarize_findings()
            if summary:
                console.print(Panel(summary, title="LLM Summary", border_style="cyan"))
                meta = getattr(session, "last_llm_meta", None) or {}
                usage = meta.get("usage") if isinstance(meta, dict) else None
                if isinstance(usage, dict):
                    total = usage.get("total_tokens")
                    prompt = usage.get("prompt_tokens")
                    completion = usage.get("completion_tokens")
                    cost = meta.get("cost_usd")
                    parts = []
                    if total is not None:
                        parts.append(f"tokens={total}")
                    if prompt is not None and completion is not None:
                        parts.append(f"prompt={prompt} completion={completion}")
                    if cost is not None:
                        parts.append(f"cost_usd={cost:.6f}" if isinstance(cost, (int, float)) else f"cost_usd={cost}")
                    if parts:
                        console.print(f"[dim]LLM usage: {' | '.join(parts)}[/dim]")
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
            resp = session.remediate(title=title, evidence=evidence)
            if resp:
                console.print(Panel(resp, title="LLM Fix", border_style="green"))
                meta = getattr(session, "last_llm_meta", None) or {}
                usage = meta.get("usage") if isinstance(meta, dict) else None
                if isinstance(usage, dict):
                    total = usage.get("total_tokens")
                    prompt = usage.get("prompt_tokens")
                    completion = usage.get("completion_tokens")
                    cost = meta.get("cost_usd")
                    parts = []
                    if total is not None:
                        parts.append(f"tokens={total}")
                    if prompt is not None and completion is not None:
                        parts.append(f"prompt={prompt} completion={completion}")
                    if cost is not None:
                        parts.append(f"cost_usd={cost:.6f}" if isinstance(cost, (int, float)) else f"cost_usd={cost}")
                    if parts:
                        console.print(f"[dim]LLM usage: {' | '.join(parts)}[/dim]")
            else:
                console.print("[yellow]No fix available (LLM error).[/yellow]")
            continue

        if user_input.startswith("/plan"):
            plan = session.plan_next()
            console.print(Panel(json.dumps(plan, indent=2), title="Next Steps", border_style="cyan"))
            continue

        if user_input.startswith("/report"):
            parts = shlex.split(user_input)
            path = Path(parts[1]) if len(parts) > 1 else Path("chat_report.json")
            res = session.save_report(path)
            if res.get("success"):
                console.print(f"[green]Saved report to {res['path']}[/green]")
            else:
                console.print(f"[red]Failed to save report:[/red] {res.get('error','')}")
            continue

        if user_input.startswith("/test"):
            console.print("[cyan]Running unit tests...[/cyan]")
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
            console.print("[yellow]No suggestions available. Use slash commands: /scan, /audit, /details, /report, /test, /summary, /fix, /plan[/yellow]")
        else:
            console.print(Panel("\n".join(lines), title="Engagement Planner", border_style="cyan"))

if __name__ == "__main__":
    app()
