import os
import yaml
import typer
from pathlib import Path
from rich.console import Console
from typing import Dict, Any

console = Console()

# Define paths
APP_NAME = "supabash"

# Prefer a repo-local config.yaml; fall back to ~/.supabash/config.yaml for compatibility
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT
CONFIG_FILE = CONFIG_DIR / "config.yaml"
FALLBACK_CONFIG_DIR = Path.home() / f".{APP_NAME}"
FALLBACK_CONFIG_FILE = FALLBACK_CONFIG_DIR / "config.yaml"

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
    }
}

class ConfigManager:
    def __init__(self):
        self.config_file = CONFIG_FILE
        self.fallback_file = FALLBACK_CONFIG_FILE
        # Ensure target dir exists
        if not self.config_file.parent.exists():
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.fallback_file.parent.exists():
            self.fallback_file.parent.mkdir(parents=True, exist_ok=True)

        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """
        Loads config. If missing in the project root, falls back to ~/.supabash,
        otherwise creates a default project config.
        """
        target_file = self.config_file if self.config_file.exists() else None
        use_fallback = False
        if not target_file and self.fallback_file.exists():
            target_file = self.fallback_file
            use_fallback = True
            self.config_file = target_file

        if not target_file:
            console.print(f"[yellow][!] Configuration file not found.[/yellow]")
            console.print(f"[green][*] Generating default config at: {self.config_file}[/green]")
            
            self.save_config(DEFAULT_CONFIG)
                
            console.print(f"\n[bold red]ACTION REQUIRED:[/bold red] Please edit {self.config_file} and add your API Key.")
            console.print("Or use: [bold cyan]supabash config --help[/bold cyan] to set it via CLI.")
            # We don't raise Exit here because we want the CLI 'config' command to still work
            # even if the file was just created. But other commands should check this.
            return DEFAULT_CONFIG

        try:
            with open(self.config_file, "r") as f:
                loaded = yaml.safe_load(f)
                if not loaded:
                    return DEFAULT_CONFIG
                # Basic merge to ensure structure
                if "llm" not in loaded:
                    loaded["llm"] = DEFAULT_CONFIG["llm"]
                if use_fallback:
                    # Migrate legacy user config into project-local config.yaml
                    self.config_file = CONFIG_FILE
                    self.save_config(loaded)
                return loaded
        except Exception as e:
            console.print(f"[bold red]Error parsing config file:[/bold red] {e}")
            raise typer.Exit(code=1)

    def save_config(self, new_config: Dict[str, Any]):
        """Saves configuration to the YAML file."""
        try:
            with open(self.config_file, "w") as f:
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
