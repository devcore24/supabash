import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from supabash.logger import setup_logger
from supabash.config import config_manager
from supabash.tools.nmap import NmapScanner
from supabash.tools.masscan import MasscanScanner
from supabash.tools.rustscan import RustscanScanner
from supabash.audit import AuditOrchestrator

app = typer.Typer(
    name="supabash",
    help="SupaBash: The Autonomous AI Security Audit Agent",
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
    SupaBash Entry Point.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[bold green]Welcome to SupaBash![/bold green]")
        console.print("Use [bold cyan]--help[/bold cyan] to see available commands.")

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or Domain to scan"),
    profile: str = typer.Option("fast", "--profile", "-p", help="Scan profile: fast, full, stealth"),
    scanner_name: str = typer.Option("nmap", "--scanner", "-s", help="Scanner engine: nmap, masscan, rustscan"),
):
    """
    Launch a basic reconnaissance scan against a target.
    """
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
        rate = 1000
        if profile == "full":
            ports = "1-65535"
            rate = 5000
        elif profile == "stealth":
            rate = 100
        extra_kwargs["rate"] = rate
    elif scanner_name == "rustscan":
        ports = "1-1000"
        batch = 2000
        if profile == "full":
            ports = "1-65535"
            batch = 5000
        elif profile == "stealth":
            batch = 1000
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
):
    """
    Run a full security audit (Infrastructure + Web + Container).
    """
    logger.info(f"Command 'audit' triggered for target: {target}")
    console.print(f"[bold red][*] initializing full audit protocol for {target}...[/bold red]")
    if container_image:
        console.print(f"[dim]Including container image: {container_image}[/dim]")
    console.print(f"[dim]Results will be saved to {output}[/dim]")

    orchestrator = AuditOrchestrator()
    with console.status("[bold green]Running audit steps...[/bold green]"):
        report = orchestrator.run(target, Path(output), container_image=container_image)

    saved_path = report.get("saved_to")
    if saved_path:
        console.print(f"[bold green]Audit complete.[/bold green] Report saved to [cyan]{saved_path}[/cyan]")
    else:
        console.print("[yellow]Audit completed but failed to write report file.[/yellow]")
        if "write_error" in report:
            console.print(f"[red]{report['write_error']}[/red]")

@app.command()
def config(
    provider: str = typer.Option(None, "--provider", "-p", help="Set active AI Provider (openai, anthropic, gemini)"),
    key: str = typer.Option(None, "--key", "-k", help="Set API Key for the selected/active provider"),
    model: str = typer.Option(None, "--model", "-m", help="Set Model name for the selected/active provider")
):
    """
    View or update configuration settings.
    """
    logger.info("Command 'config' triggered")
    console.print(Panel("[bold green]Configuration Manager[/bold green]", expand=False))
    
    # 1. Handle Flags (Non-Interactive Mode)
    if provider or key or model:
        current_llm = config_manager.get_llm_config()
        # Determine which provider we are editing (defaults to active if not specified)
        target_provider = provider if provider else current_llm["provider"]
        
        # Validate provider
        if target_provider not in ["openai", "anthropic", "gemini"]:
             # If user wants to add a custom one, we allow it, but warn
             console.print(f"[yellow]Warning: '{target_provider}' is not a standard provider.[/yellow]")

        if provider:
            config_manager.set_active_provider(provider)
            console.print(f"Active provider set to: [cyan]{provider}[/cyan]")
        
        if key:
            config_manager.set_llm_key(target_provider, key)
            console.print(f"API Key updated for: [cyan]{target_provider}[/cyan]")
            
        if model:
            config_manager.set_model(target_provider, model)
            console.print(f"Model updated for [cyan]{target_provider}[/cyan] to: [green]{model}[/green]")
            
        console.print(f"[bold green]Configuration saved to {config_manager.config_file}[/bold green]")
        return

    # 2. Interactive Mode (Default)
    llm_config = config_manager.config.get("llm", {})
    current_provider = llm_config.get("provider", "openai")
    
    available_providers = [k for k in llm_config.keys() if k != "provider"]
    
    console.print(f"Current Active Provider: [bold cyan]{current_provider.upper()}[/bold cyan]")
    console.print(f"Config File: [dim]{config_manager.config_file}[/dim]")
    console.print("\n[bold]Available Providers:[/bold]")
    
    if not available_providers:
        console.print("[yellow]No providers configured yet. Add one to get started.[/yellow]")
    else:
        for i, prov in enumerate(available_providers, 1):
            is_active = " (Active)" if prov == current_provider else ""
            details = llm_config[prov]
            model_name = details.get("model", "unknown")
            key_status = "OK" if details.get("api_key") and details.get("api_key") != "YOUR_KEY_HERE" else "MISSING"
            
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
            
        new_key = typer.prompt("Enter API Key (or 'None' for local)", hide_input=True)
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
    console.print("[bold magenta][*] Entering Interactive Chat Mode...[/bold magenta]")
    console.print("[dim]Type 'exit' to quit.[/dim]")
    # Placeholder for Phase 3 implementation
    console.print("[yellow][!] This is a placeholder. Logic coming in Phase 3.[/yellow]")

if __name__ == "__main__":
    app()
