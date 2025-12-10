import os
from typing import List, Dict, Any, Optional

import litellm

from supabash.config import config_manager
from supabash.logger import setup_logger

logger = setup_logger(__name__)


class LLMClient:
    """
    Thin wrapper around litellm to centralize provider/model/key selection.
    """

    def __init__(self, config=None):
        self.config = config if config is not None else config_manager

    def _active_settings(self) -> Dict[str, Any]:
        cfg = self.config.config.get("llm", {})
        provider = cfg.get("provider", "openai")
        provider_cfg = cfg.get(provider, {})
        api_key = provider_cfg.get("api_key")
        model = provider_cfg.get("model")
        api_base = provider_cfg.get("api_base")

        if not api_key or api_key == "YOUR_KEY_HERE":
            raise ValueError(f"Missing API key for provider '{provider}'. Set it via config.")
        if not model:
            raise ValueError(f"Missing model for provider '{provider}'. Set it via config.")

        return {
            "provider": provider,
            "model": model,
            "api_key": api_key,
            "api_base": api_base,
        }

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        """
        Send chat messages to the configured LLM and return the assistant content.
        """
        settings = self._active_settings()
        kwargs = {
            "model": settings["model"],
            "messages": messages,
            "temperature": temperature,
            "api_key": settings["api_key"],
        }
        if settings.get("api_base"):
            kwargs["api_base"] = settings["api_base"]

        logger.debug(f"Dispatching chat to model={settings['model']} provider={settings['provider']}")
        try:
            response = litellm.completion(**kwargs)
            return response["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            raise
