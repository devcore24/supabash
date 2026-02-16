import os
import yaml
import typer
from pathlib import Path
from rich.console import Console
from typing import Dict, Any, List

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
        "save_reports": True,
        "allowed_hosts": ["localhost", "127.0.0.1"],
        "consent_accepted": False,
        # Safety: require explicit opt-in for public IP targets
        "allow_public_ips": False,
        # Safety caps for aggressive mode (global rate limits / concurrency caps)
        # These prevent accidental noisy behavior even in aggressive mode.
        "aggressive_caps": {
            "max_nuclei_rate": 20,
            "default_nuclei_rate": 10,
            "max_gobuster_threads": 50,
            "max_parallel_workers": 6,
        },
        # Optional report exports (require extra dependencies)
        "report_exports": {
            "html": False,
            "pdf": False,
        },
    },
    # Chat UX + memory controls (used by `supabash chat`)
    "chat": {
        # Persist a bounded message history to `.supabash/chat_state.json`.
        "history_max_messages": 80,
        "max_message_chars": 4000,
        # Include last N user/assistant turns in each LLM call.
        "llm_history_turns": 6,
        # Rolling summary memory (0 disables auto-summarization).
        "summary_every_turns": 4,
        "summary_keep_last_messages": 24,
        "max_summary_chars": 1200,
        # Redact secrets from chat history/state.
        "redact_secrets": True,
    },
    # Tool registry (enable/disable tools globally)
    # Note: some tools are also conditional/opt-in at runtime (e.g. sqlmap requires a parameterized URL).
    "tools": {
        "nmap": {
            "enabled": True,
            "timeout_seconds": 600,
            # Fast discovery before nmap service detection (rustscan/masscan + targeted nmap).
            "fast_discovery": True,
            "fast_discovery_ports": "1-65535",
            "fast_discovery_max_ports": 256,
        },
        "masscan": {"enabled": True, "timeout_seconds": 600, "rate": 1000, "ports": "1-65535"},
        "rustscan": {"enabled": True, "timeout_seconds": 600, "batch": 2000, "ports": "1-65535"},
        # Subdomain discovery (domain targets only; many sources require API keys)
        "subfinder": {
            "enabled": False,
            "timeout_seconds": 600,
            # Bound and validate discovered hosts before promoting to web probing.
            "max_candidates": 200,
            "max_promoted_hosts": 40,
            "resolve_validation": True,
        },
        "httpx": {"enabled": True, "timeout_seconds": 300},
        "whatweb": {"enabled": True, "timeout_seconds": 300},
        "nuclei": {
            "enabled": True,
            "timeout_seconds": 1800,
            "rate_limit": 10,
            "tags": "",
            "severity": "",
        },
        "gobuster": {"enabled": True, "timeout_seconds": 1800},
        # Content discovery (alternative/fallback to gobuster; keep opt-in by default to reduce noise)
        "ffuf": {"enabled": False, "timeout_seconds": 1800},
        # Crawling/spidering (attack-surface expansion; opt-in for noise control)
        "katana": {"enabled": False, "timeout_seconds": 1800, "depth": 3, "concurrency": 10},
        "sqlmap": {"enabled": True, "timeout_seconds": 1800},
        # Slow/noisy: keep opt-in by default
        "nikto": {"enabled": False, "timeout_seconds": 1200},
        "sslscan": {"enabled": True, "timeout_seconds": 600},
        "dnsenum": {"enabled": True, "timeout_seconds": 900},
        # Prefer underscore in config keys for readability; both forms are accepted by the runtime.
        "enum4linux_ng": {"enabled": True, "timeout_seconds": 1200},
        # Informational only: offline exploit reference lookups based on service fingerprints (opt-in)
        "searchsploit": {"enabled": False, "timeout_seconds": 120},
        "trivy": {"enabled": True, "timeout_seconds": 1800},
        "supabase_audit": {"enabled": True, "timeout_seconds": 10, "max_pages": 5, "extra_urls": []},
        "readiness_probe": {"enabled": True, "max_web_targets": 30},
        # Credentials brute forcing should remain opt-in/manual for safety.
        "hydra": {"enabled": False, "timeout_seconds": 3600},
    },
    "llm": {
        # Global kill-switch: disable all LLM calls (offline/no-LLM mode).
        "enabled": True,
        # Optional privacy guard: when true, only local providers are allowed (ollama/lmstudio).
        "local_only": False,
        "max_input_chars": 12000,
        # Optional fallback for context-window display in chat (used when model info is unknown).
        # Set this for local models (e.g. LM Studio) if you want accurate % reporting.
        "max_input_tokens": 0,
        "cache_enabled": False,
        "cache_ttl_seconds": 3600,
        "cache_max_entries": 500,
        "provider": "openai",  # active provider: openai, anthropic, gemini, ollama, lmstudio
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
        },
        # Local models via Ollama (no API key required)
        "ollama": {
            "api_key": None,
            "model": "ollama/llama3.1",
            "api_base": "http://localhost:11434",
        }
        ,
        # Local models via LM Studio (OpenAI-compatible; no API key required)
        "lmstudio": {
            "api_key": None,
            "model": "local-model",
            "api_base": "http://localhost:1234/v1",
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
                if "core" not in loaded:
                    loaded["core"] = DEFAULT_CONFIG["core"]
                else:
                    for k, v in DEFAULT_CONFIG["core"].items():
                        loaded["core"].setdefault(k, v)
                if "llm" not in loaded:
                    loaded["llm"] = DEFAULT_CONFIG["llm"]
                else:
                    for k, v in DEFAULT_CONFIG["llm"].items():
                        if isinstance(v, dict):
                            loaded["llm"].setdefault(k, v)
                        else:
                            loaded["llm"].setdefault(k, v)
                if "chat" not in loaded:
                    loaded["chat"] = DEFAULT_CONFIG.get("chat", {})
                else:
                    default_chat = DEFAULT_CONFIG.get("chat", {})
                    if isinstance(default_chat, dict) and isinstance(loaded.get("chat"), dict):
                        for k, v in default_chat.items():
                            loaded["chat"].setdefault(k, v)
                    else:
                        loaded["chat"] = DEFAULT_CONFIG.get("chat", {})
                if "tools" not in loaded:
                    loaded["tools"] = DEFAULT_CONFIG["tools"]
                else:
                    default_tools = DEFAULT_CONFIG.get("tools", {})
                    if isinstance(default_tools, dict) and isinstance(loaded.get("tools"), dict):
                        tools_cfg = loaded["tools"]
                        for k, v in default_tools.items():
                            variants = [k]
                            if isinstance(k, str) and "_" in k:
                                variants.append(k.replace("_", "-"))
                            if isinstance(k, str) and "-" in k:
                                variants.append(k.replace("-", "_"))

                            present = [vv for vv in variants if vv in tools_cfg]
                            if not present:
                                tools_cfg[k] = v
                                continue

                            for key in present:
                                existing = tools_cfg.get(key)
                                if isinstance(existing, dict) and isinstance(v, dict):
                                    for dk, dv in v.items():
                                        existing.setdefault(dk, dv)
                                else:
                                    tools_cfg[key] = v
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

    def set_api_base(self, provider: str, api_base: str):
        if provider not in self.config["llm"]:
            self.config["llm"][provider] = {}
        if api_base is None or str(api_base).strip() == "":
            self.config["llm"][provider].pop("api_base", None)
        else:
            self.config["llm"][provider]["api_base"] = str(api_base).strip()
        self.save_config(self.config)

    def get_allowed_hosts(self) -> List[str]:
        core = self.config.setdefault("core", {})
        return list(core.get("allowed_hosts", []))

    def add_allowed_host(self, entry: str):
        core = self.config.setdefault("core", {})
        allowed = core.setdefault("allowed_hosts", [])
        if entry not in allowed:
            allowed.append(entry)
        self.save_config(self.config)

    def remove_allowed_host(self, entry: str):
        core = self.config.setdefault("core", {})
        allowed = core.setdefault("allowed_hosts", [])
        core["allowed_hosts"] = [x for x in allowed if x != entry]
        self.save_config(self.config)

    def set_consent_accepted(self, accepted: bool):
        core = self.config.setdefault("core", {})
        core["consent_accepted"] = bool(accepted)
        self.save_config(self.config)

    def get_allow_public_ips(self) -> bool:
        core = self.config.setdefault("core", {})
        return bool(core.get("allow_public_ips", False))

    def set_allow_public_ips(self, allowed: bool):
        core = self.config.setdefault("core", {})
        core["allow_public_ips"] = bool(allowed)
        self.save_config(self.config)

# Singleton instance
config_manager = ConfigManager()
