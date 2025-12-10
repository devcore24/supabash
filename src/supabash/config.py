import os
import yaml
import typer
from pathlib import Path
from rich.console import Console
from typing import Dict, Any

console = Console()

# Define paths
APP_NAME = "supabash"
CONFIG_DIR = Path.home() / f".{APP_NAME}"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Default Template
DEFAULT_CONFIG = {
    "core": {
        "log_level": "INFO",
        "save_reports": True
    },
    "llm": {
        "provider": "openai",  # active provider: openai, anthropic, gemini
        "openai": {
            "api_key": "YOUR_KEY_HERE",
            "model": "gpt-4-turbo"
        },
        "anthropic": {
            "api_key": "YOUR_KEY_HERE",
            "model": "claude-3-opus-20240229"
        },
        "gemini": {
            "api_key": "YOUR_KEY_HERE",
            "model": "gemini-1.5-pro-latest"
        }
    },
    "targets": {
        "allowed_hosts": ["localhost", "127.0.0.1"]
    }
}

class ConfigManager:
    def __init__(self):
        self.config_file = CONFIG_FILE
        # Ensure dir exists
        if not CONFIG_DIR.exists():
            CONFIG_DIR.mkdir(parents=True)
        
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """
        Loads config. If missing, creates a default one and notifies the user.
        """
        if not CONFIG_FILE.exists():
            console.print(f"[yellow][!] Configuration file not found.[/yellow]")
            console.print(f"[green][*] Generating default config at: {CONFIG_FILE}[/green]")
            
            self.save_config(DEFAULT_CONFIG)
                
            console.print(f"\n[bold red]ACTION REQUIRED:[/bold red] Please edit {CONFIG_FILE} and add your API Key.")
            console.print("Or use: [bold cyan]supabash config --help[/bold cyan] to set it via CLI.")
            # We don't raise Exit here because we want the CLI 'config' command to still work
            # even if the file was just created. But other commands should check this.
            return DEFAULT_CONFIG

        try:
            with open(CONFIG_FILE, "r") as f:
                loaded = yaml.safe_load(f)
                if not loaded:
                    return DEFAULT_CONFIG
                # Basic merge to ensure structure
                if "llm" not in loaded:
                    loaded["llm"] = DEFAULT_CONFIG["llm"]
                return loaded
        except Exception as e:
            console.print(f"[bold red]Error parsing config file:[/bold red] {e}")
            raise typer.Exit(code=1)

    def save_config(self, new_config: Dict[str, Any]):
        """Saves configuration to the YAML file."""
        try:
            with open(CONFIG_FILE, "w") as f:
                yaml.dump(new_config, f, default_flow_style=False, sort_keys=False)
            self.config = new_config
        except Exception as e:
            console.print(f"[red]Error saving config: {e}[/red]")

    def get_llm_config(self):
        """Returns the active LLM configuration."""
        llm = self.config.get("llm", DEFAULT_CONFIG["llm"])
        provider = llm.get("provider", "openai")
        return {
            "provider": provider,
            "config": llm.get(provider, {})
        }

    def set_llm_key(self, provider: str, api_key: str):
        """Sets the API key for a specific provider."""
        if "llm" not in self.config:
            self.config["llm"] = DEFAULT_CONFIG["llm"]
        
        if provider not in self.config["llm"]:
            self.config["llm"][provider] = {}
            
        self.config["llm"][provider]["api_key"] = api_key
        self.save_config(self.config)

    def set_active_provider(self, provider: str):
        """Sets the active LLM provider."""
        if "llm" not in self.config:
            self.config["llm"] = DEFAULT_CONFIG["llm"]
        self.config["llm"]["provider"] = provider
        self.save_config(self.config)

    def set_model(self, provider: str, model: str):
        """Sets the model for a specific provider."""
        if provider not in self.config["llm"]:
            self.config["llm"][provider] = {}
        self.config["llm"][provider]["model"] = model
        self.save_config(self.config)

# Singleton instance
config_manager = ConfigManager()
