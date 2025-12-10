import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from supabash.logger import setup_logger
from supabash.config import config_manager

app = typer.Typer(
    name="supabash",
    help="SupaBash: The Autonomous AI Security Audit Agent",
    add_completion=False,
)
console = Console()
logger = setup_logger()

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
):
    """
    Launch a basic reconnaissance scan against a target.
    """
    logger.info(f"Command 'scan' triggered for target: {target} with profile: {profile}")
    console.print(f"[bold blue][*] Starting {profile} scan against {target}...[/bold blue]")
    # Placeholder for Phase 2 implementation
    console.print("[yellow][!] This is a placeholder. Logic coming in Phase 2.[/yellow]")

@app.command()
def audit(
    target: str = typer.Argument(..., help="Target IP, URL, or Container ID"),
    output: str = typer.Option("report.json", "--output", "-o", help="Output file path"),
):
    """
    Run a full security audit (Infrastructure + Web + Container).
    """
    logger.info(f"Command 'audit' triggered for target: {target}")
    console.print(f"[bold red][*] initializing full audit protocol for {target}...[/bold red]")
    console.print(f"[dim]Results will be saved to {output}[/dim]")
    # Placeholder for Phase 2 implementation
    console.print("[yellow][!] This is a placeholder. Logic coming in Phase 2.[/yellow]")

@app.command()
def config():
    """
    Interactive configuration (API keys, settings).
    """
    logger.info("Command 'config' triggered")
    console.print(Panel("[bold green]Configuration Manager[/bold green]", expand=False))
    
    current_key = config_manager.get("openai_api_key")
    masked_key = f"{current_key[:6]}...{current_key[-4:]}" if current_key and len(current_key) > 10 else "Not Set"
    
    console.print(f"Current OpenAI API Key: [cyan]{masked_key}[/cyan]")
    
    if typer.confirm("Do you want to update the OpenAI API Key?"):
        new_key = typer.prompt("Enter new OpenAI API Key", hide_input=True)
        config_manager.set("openai_api_key", new_key)
        console.print("[green]API Key updated successfully![/green]")
    else:
        console.print("[dim]No changes made.[/dim]")
    
    console.print(f"\n[bold]Current Config File:[/bold] {config_manager.config_file}")

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
