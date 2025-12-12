import os
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import litellm

from supabash.config import config_manager
from supabash.logger import setup_logger
from supabash.llm_cache import CacheSettings, LLMCache, make_cache_key

logger = setup_logger(__name__)


class LLMClient:
    """
    Thin wrapper around litellm to centralize provider/model/key selection.
    """

    def __init__(self, config=None):
        self.config = config if config is not None else config_manager

    def _cache(self) -> Optional[LLMCache]:
        try:
            llm_cfg = self.config.config.get("llm", {})
            enabled = bool(llm_cfg.get("cache_enabled", False))
            ttl = int(llm_cfg.get("cache_ttl_seconds", 3600))
            max_entries = int(llm_cfg.get("cache_max_entries", 500))
            cache_dir = llm_cfg.get("cache_dir")
            if cache_dir:
                dir_path = Path(cache_dir).expanduser()
            else:
                dir_path = Path.home() / f".supabash" / "cache" / "llm"
            return LLMCache(CacheSettings(enabled=enabled, dir=dir_path, ttl_seconds=ttl, max_entries=max_entries))
        except Exception:
            return None

    def _active_settings(self) -> Dict[str, Any]:
        cfg = self.config.config.get("llm", {})
        provider = cfg.get("provider", "openai")
        provider_cfg = cfg.get(provider, {})
        api_key = provider_cfg.get("api_key")
        model = provider_cfg.get("model")
        api_base = provider_cfg.get("api_base")

        # Local/OpenAI-compatible backends that don't require an API key.
        keyless_providers = {"ollama", "lmstudio"}

        def normalize_key(value: Any) -> Optional[str]:
            if value is None:
                return None
            if isinstance(value, str):
                v = value.strip()
                if not v:
                    return None
                if v.lower() in ("none", "null"):
                    return None
                if v == "YOUR_KEY_HERE":
                    return None
                return v
            return None

        api_key = normalize_key(api_key)

        if provider not in keyless_providers and not api_key:
            raise ValueError(f"Missing API key for provider '{provider}'. Set it via config.")
        if not model:
            raise ValueError(f"Missing model for provider '{provider}'. Set it via config.")

        return {
            "provider": provider,
            "model": model,
            "api_key": api_key,
            "api_base": api_base,
        }

    def completion(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> Dict[str, Any]:
        """
        Send a completion request to the configured LLM and return the raw response.
        """
        settings = self._active_settings()
        cache = self._cache()
        cache_key = None
        if cache is not None and cache.settings.enabled:
            cache_key = make_cache_key(
                {
                    "provider": settings["provider"],
                    "model": settings["model"],
                    "temperature": temperature,
                    "messages": messages,
                }
            )
            cached = cache.get(cache_key)
            if cached is not None:
                content, meta = cached
                usage = meta.get("usage")
                return {
                    "choices": [{"message": {"content": content}}],
                    "usage": usage if isinstance(usage, dict) else None,
                    "_cached": True,
                    "_cache_key": cache_key,
                    "_cached_meta": meta,
                }
        kwargs = {
            "model": settings["model"],
            "messages": messages,
            "temperature": temperature,
        }
        if settings.get("api_key"):
            kwargs["api_key"] = settings["api_key"]
        if settings.get("api_base"):
            kwargs["api_base"] = settings["api_base"]

        logger.debug(f"Dispatching chat to model={settings['model']} provider={settings['provider']}")
        try:
            resp = litellm.completion(**kwargs)
            if cache is not None and cache.settings.enabled and cache_key:
                try:
                    content = resp["choices"][0]["message"]["content"]
                    meta = {"usage": resp.get("usage"), "provider": settings["provider"], "model": settings["model"]}
                    completion_cost = getattr(litellm, "completion_cost", None)
                    if callable(completion_cost):
                        try:
                            meta["cost_usd"] = float(completion_cost(resp))
                        except Exception:
                            pass
                    cache.set(cache_key, content, meta)
                except Exception:
                    pass
            return resp
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            raise

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        """
        Send chat messages to the configured LLM and return the assistant content.
        """
        response = self.completion(messages, temperature=temperature)
        return response["choices"][0]["message"]["content"]

    def chat_with_meta(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> Tuple[str, Dict[str, Any]]:
        """
        Returns (content, meta) where meta includes best-effort usage + cost estimation.
        """
        settings = self._active_settings()
        response = self.completion(messages, temperature=temperature)
        content = response["choices"][0]["message"]["content"]

        cached_meta = response.get("_cached_meta")
        if isinstance(cached_meta, dict):
            meta = dict(cached_meta)
            meta.setdefault("provider", settings.get("provider"))
            meta.setdefault("model", settings.get("model"))
            meta["cached"] = True
            meta["cache_key"] = response.get("_cache_key")
            return content, meta

        usage = response.get("usage") or {}
        cost_usd = None
        completion_cost = getattr(litellm, "completion_cost", None)
        if callable(completion_cost):
            try:
                cost_usd = completion_cost(response)
            except Exception:
                cost_usd = None

        meta = {
            "provider": settings.get("provider"),
            "model": settings.get("model"),
            "usage": usage if isinstance(usage, dict) else {"raw": usage},
        }
        if response.get("_cached"):
            meta["cached"] = True
            meta["cache_key"] = response.get("_cache_key")
        if cost_usd is not None:
            meta["cost_usd"] = float(cost_usd)
        return content, meta
