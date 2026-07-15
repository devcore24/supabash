import copy
import os
import tempfile
import yaml
import typer
from pathlib import Path
from rich.console import Console
from typing import Dict, Any, List

console = Console()
# Define paths
APP_NAME = "supabash"


def resolve_config_file(
    *,
    cwd: Path = None,
    home: Path = None,
    environ: Dict[str, str] = None,
    source_root: Path = None,
) -> Path:
    """Resolve a writable config path without assuming a source-checkout layout."""
    env = environ if isinstance(environ, dict) else os.environ
    explicit = str(env.get("SUPABASH_CONFIG") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()

    current = Path(cwd) if cwd is not None else Path.cwd()
    local = current / "config.yaml"
    if local.exists():
        return local.resolve()

    source = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[2]
    if (source / "pyproject.toml").is_file():
        return (source / "config.yaml").resolve()

    user_home = Path(home) if home is not None else Path.home()
    xdg_home = str(env.get("XDG_CONFIG_HOME") or "").strip()
    config_home = Path(xdg_home).expanduser() if xdg_home else user_home / ".config"
    return (config_home / APP_NAME / "config.yaml").resolve()


CONFIG_FILE = resolve_config_file()
CONFIG_DIR = CONFIG_FILE.parent
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
    # Experimental Codex CLI planner backend (used by `ai-audit --agent-backend codex`).
    # Codex proposes actions; Supabash remains responsible for scope validation,
    # wrapper execution, evidence collection, and report generation.
    "codex": {
        "command": "codex",
        # Optional dedicated auth-only Codex home. Authenticate this home separately
        # and keep global AGENTS files absent/empty so planner context stays isolated.
        "codex_home": None,
        "timeout_seconds": 300,
        "preflight_timeout_seconds": 10,
        "sandbox": "read-only",
        "require_chatgpt": True,
        "ignore_user_config": True,
        "persistent_thread": False,
        "max_input_chars": 24000,
        "max_events": 500,
        "max_event_chars": 16384,
        # Codex is a reasoning-only planner here; Supabash owns all tool execution.
        "disabled_features": [
            "plugins",
            "remote_plugin",
            "apps",
            "shell_tool",
            "browser_use",
            "computer_use",
            "in_app_browser",
            "image_generation",
            "multi_agent",
            "workspace_dependencies",
        ],
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
            "normal_mode_broad_rate_limit": 0,
            "tags": "",
            "severity": "",
        },
        "gobuster": {"enabled": True, "timeout_seconds": 1800},
        # Content discovery (alternative/fallback to gobuster; keep opt-in by default to reduce noise)
        "ffuf": {"enabled": False, "timeout_seconds": 1800},
        # Crawling/spidering (attack-surface expansion; opt-in for noise control)
        "katana": {"enabled": True, "timeout_seconds": 1800, "depth": 3, "concurrency": 10},
        # Browser-driven exploration (agentic tool only; enabled by default but auto-skips when CLI is unavailable).
        "browser_use": {
            "enabled": True,
            "timeout_seconds": 900,
            "max_steps": 25,
            "min_steps_success": 1,
            "require_done": True,
            "headless": True,
            # Optional browser-use cloud API key; Supabash exports it as
            # BROWSER_USE_API_KEY when invoking the browser-use CLI.
            "api_key": "",
            # Optional alternate environment variable name to read when api_key is empty.
            "api_key_env": "",
            # Optional browser-use session/profile for authenticated workflows.
            "session": "",
            "profile": "",
            # Optional auth guidance for browser tasks (kept generic by default).
            "auth": {
                "enabled": False,
                "login_url": "",
                "notes": "",
                # Optional direct values (discouraged) or env-backed values.
                "username": "",
                "password": "",
                "cookie": "",
                "username_env": "",
                "password_env": "",
                "cookie_env": "",
                # When false (default), secrets are never injected into the task text.
                "include_secrets_in_task": False,
            },
            # Optional command template override, supports placeholders:
            # {target}, {task}, {max_steps}, {headless}, {model}, {session}, {profile}
            "command": "",
            "model": "",
        },
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
        self.config = self.load_config()

    @staticmethod
    def _harden_config_permissions(path: Path) -> None:
        """Best-effort hardening for an existing credential-bearing config."""
        try:
            if path.is_file():
                path.chmod(0o600)
        except OSError as e:
            console.print(f"[yellow]Warning: unable to restrict config permissions for {path}: {e}[/yellow]")

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
            self._harden_config_permissions(target_file)
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
                default_codex = DEFAULT_CONFIG.get("codex", {})
                if not isinstance(loaded.get("codex"), dict):
                    loaded["codex"] = copy.deepcopy(default_codex)
                else:
                    for k, v in default_codex.items():
                        loaded["codex"].setdefault(k, copy.deepcopy(v))
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

    def save_config(self, new_config: Dict[str, Any]) -> bool:
        """Atomically save configuration with owner-only permissions."""
        temp_path = None
        fd = -1
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.config_file.name}.",
                suffix=".tmp",
                dir=str(self.config_file.parent),
            )
            temp_path = Path(temp_name)
            os.fchmod(fd, 0o600)
            handle = os.fdopen(fd, "w", encoding="utf-8")
            fd = -1
            with handle:
                yaml.safe_dump(new_config, handle, default_flow_style=False, sort_keys=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.config_file)
            self.config_file.chmod(0o600)
            self.config = copy.deepcopy(new_config)
            return True
        except Exception as e:
            console.print(f"[red]Error saving config: {e}[/red]")
            return False
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def get_llm_config(self):
        """Returns the active LLM configuration."""
        llm = self.config.get("llm", DEFAULT_CONFIG["llm"])
        provider = llm.get("provider", "openai")
        return {
            "provider": provider,
            "config": llm.get(provider, {})
        }

    _UNSET = object()

    def _candidate_config(self) -> Dict[str, Any]:
        current = self.config if isinstance(self.config, dict) else {}
        return copy.deepcopy(current)

    def configure_llm_provider(
        self,
        provider: str,
        *,
        api_key: Any = _UNSET,
        model: Any = _UNSET,
        api_base: Any = _UNSET,
        make_active: bool = False,
    ) -> bool:
        """Atomically apply one or more LLM provider updates."""
        candidate = self._candidate_config()
        llm = candidate.get("llm")
        if not isinstance(llm, dict):
            llm = {}
            candidate["llm"] = llm

        if any(value is not self._UNSET for value in (api_key, model, api_base)):
            provider_config = llm.get(provider)
            if not isinstance(provider_config, dict):
                provider_config = {}
                llm[provider] = provider_config
            if api_key is not self._UNSET:
                provider_config["api_key"] = api_key
            if model is not self._UNSET:
                provider_config["model"] = model
            if api_base is not self._UNSET:
                normalized_base = "" if api_base is None else str(api_base).strip()
                if normalized_base:
                    provider_config["api_base"] = normalized_base
                else:
                    provider_config.pop("api_base", None)
        if make_active:
            llm["provider"] = provider
        return self.save_config(candidate)

    def set_llm_key(self, provider: str, api_key: str) -> bool:
        """Set an API key without mutating live state before persistence."""
        return self.configure_llm_provider(provider, api_key=api_key)

    def set_active_provider(self, provider: str) -> bool:
        """Set the active LLM provider."""
        return self.configure_llm_provider(provider, make_active=True)

    def set_model(self, provider: str, model: str) -> bool:
        """Set a provider model."""
        return self.configure_llm_provider(provider, model=model)

    def set_api_base(self, provider: str, api_base: str) -> bool:
        """Set or clear a provider API base URL."""
        return self.configure_llm_provider(provider, api_base=api_base)

    def get_allowed_hosts(self) -> List[str]:
        core = self.config.get("core") if isinstance(self.config, dict) else {}
        if not isinstance(core, dict):
            return []
        allowed = core.get("allowed_hosts")
        return list(allowed) if isinstance(allowed, list) else []

    def add_allowed_host(self, entry: str) -> bool:
        candidate = self._candidate_config()
        core = candidate.get("core")
        if not isinstance(core, dict):
            core = {}
            candidate["core"] = core
        allowed = core.get("allowed_hosts")
        if not isinstance(allowed, list):
            allowed = []
            core["allowed_hosts"] = allowed
        if entry not in allowed:
            allowed.append(entry)
        return self.save_config(candidate)

    def remove_allowed_host(self, entry: str) -> bool:
        candidate = self._candidate_config()
        core = candidate.get("core")
        if not isinstance(core, dict):
            core = {}
            candidate["core"] = core
        allowed = core.get("allowed_hosts")
        if not isinstance(allowed, list):
            allowed = []
        core["allowed_hosts"] = [value for value in allowed if value != entry]
        return self.save_config(candidate)

    def set_consent_accepted(self, accepted: bool) -> bool:
        candidate = self._candidate_config()
        core = candidate.get("core")
        if not isinstance(core, dict):
            core = {}
            candidate["core"] = core
        core["consent_accepted"] = bool(accepted)
        return self.save_config(candidate)

    def get_allow_public_ips(self) -> bool:
        core = self.config.get("core") if isinstance(self.config, dict) else {}
        return bool(core.get("allow_public_ips", False)) if isinstance(core, dict) else False

    def set_allow_public_ips(self, allowed: bool) -> bool:
        candidate = self._candidate_config()
        core = candidate.get("core")
        if not isinstance(core, dict):
            core = {}
            candidate["core"] = core
        core["allow_public_ips"] = bool(allowed)
        return self.save_config(candidate)

# Singleton instance
config_manager = ConfigManager()
