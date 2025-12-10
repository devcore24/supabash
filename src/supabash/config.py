import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

# Constants
CONFIG_DIR = Path.home() / ".supabash"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

DEFAULT_CONFIG = {
    "openai_api_key": "",
    "model": "gpt-4-turbo",
    "log_level": "INFO",
    "scans": {
        "output_dir": str(Path.home() / "supabash_reports"),
        "aggressiveness": "normal"  # stealth, normal, aggressive
    }
}

class ConfigManager:
    def __init__(self):
        self.config_file = CONFIG_FILE
        self._ensure_config_exists()
        self.config = self.load_config()

    def _ensure_config_exists(self):
        """Creates the config directory and file if they don't exist."""
        if not CONFIG_DIR.exists():
            os.makedirs(CONFIG_DIR, exist_ok=True)
        
        if not self.config_file.exists():
            self.save_config(DEFAULT_CONFIG)

    def load_config(self) -> Dict[str, Any]:
        """Loads configuration from the YAML file."""
        try:
            with open(self.config_file, "r") as f:
                return yaml.safe_load(f) or DEFAULT_CONFIG
        except Exception as e:
            print(f"Error loading config: {e}")
            return DEFAULT_CONFIG

    def save_config(self, config_data: Dict[str, Any]):
        """Saves configuration to the YAML file."""
        try:
            with open(self.config_file, "w") as f:
                yaml.dump(config_data, f, default_flow_style=False)
            self.config = config_data
        except Exception as e:
            print(f"Error saving config: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value by key."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any):
        """Sets a configuration value and saves to file."""
        self.config[key] = value
        self.save_config(self.config)

# Singleton instance
config_manager = ConfigManager()
