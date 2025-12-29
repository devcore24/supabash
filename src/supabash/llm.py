import os
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import litellm

from supabash.config import config_manager
from supabash.logger import setup_logger
from supabash.llm_cache import CacheSettings, LLMCache, make_cache_key

logger = setup_logger(__name__)


class ToolCallingNotSupported(RuntimeError):
    pass


class ToolCallingError(RuntimeError):
    pass


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
        local_only = bool(cfg.get("local_only", False))
        if local_only and provider not in keyless_providers:
            raise ValueError(
                "llm.local_only=true is enabled; only local providers are allowed (ollama, lmstudio)."
            )

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

    def max_input_tokens(self) -> Optional[int]:
        """
        Best-effort max input token window for the active model.
        Returns None when unknown.
        """
        cfg = self.config.config.get("llm", {})
        try:
            fallback = int(cfg.get("max_input_tokens", 0) or 0)
        except Exception:
            fallback = 0

        try:
            settings = self._active_settings()
            model = settings.get("model")
            if model:
                info = litellm.get_model_info(model)
                if isinstance(info, dict):
                    val = info.get("max_input_tokens") or info.get("max_tokens")
                    if val is not None:
                        return int(val)
        except Exception:
            pass

        return fallback if fallback > 0 else None

    def estimate_prompt_tokens(self, messages: List[Dict[str, str]]) -> Optional[int]:
        """
        Best-effort prompt token estimate for the active model/messages.
        Returns None when token counting fails.
        """
        try:
            settings = self._active_settings()
            model = settings.get("model") or ""
            if not model:
                return None
            token_counter = getattr(litellm, "token_counter", None)
            if callable(token_counter):
                return int(token_counter(model=model, messages=messages))
        except Exception:
            return None
        return None

    def context_window_usage(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Returns a dict with estimated prompt tokens and context usage percentage when possible.
        """
        est = self.estimate_prompt_tokens(messages)
        max_in = self.max_input_tokens()
        out: Dict[str, Any] = {}
        if est is not None:
            out["estimated_prompt_tokens"] = est
        if max_in is not None:
            out["max_input_tokens"] = max_in
        if est is not None and max_in:
            try:
                out["context_usage_pct"] = round((float(est) / float(max_in)) * 100.0, 2)
            except Exception:
                pass
        return out

    def _normalize_usage(self, usage: Any) -> Dict[str, Any]:
        if usage is None:
            return {}
        if isinstance(usage, dict):
            return usage
        # Pydantic v2
        model_dump = getattr(usage, "model_dump", None)
        if callable(model_dump):
            try:
                out = model_dump()
                return out if isinstance(out, dict) else {"raw": str(usage)}
            except Exception:
                pass
        # Pydantic v1
        dict_fn = getattr(usage, "dict", None)
        if callable(dict_fn):
            try:
                out = dict_fn()
                return out if isinstance(out, dict) else {"raw": str(usage)}
            except Exception:
                pass
        # Common litellm Usage-like object
        keys = ("prompt_tokens", "completion_tokens", "total_tokens")
        if all(hasattr(usage, k) for k in keys):
            try:
                return {k: int(getattr(usage, k)) for k in keys}
            except Exception:
                pass
        try:
            d = getattr(usage, "__dict__", None)
            if isinstance(d, dict) and d:
                safe = {}
                for k, v in d.items():
                    if isinstance(v, (int, float, str, bool)) or v is None:
                        safe[str(k)] = v
                    else:
                        safe[str(k)] = str(v)
                return safe
        except Exception:
            pass
        return {"raw": str(usage)}

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
                usage = self._normalize_usage(meta.get("usage"))
                return {
                    "choices": [{"message": {"content": content}}],
                    "usage": usage if usage else None,
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
                    meta = {
                        "usage": self._normalize_usage(resp.get("usage")),
                        "provider": settings["provider"],
                        "model": settings["model"],
                    }
                    completion_cost = getattr(litellm, "completion_cost", None)
                    if callable(completion_cost):
                        try:
                            meta["cost_usd"] = float(completion_cost(resp))
                        except Exception:
                            pass
                    cache.set(cache_key, content, meta)
                except Exception:
                    pass
            try:
                resp_usage = self._normalize_usage(resp.get("usage"))
                if resp_usage:
                    resp["usage"] = resp_usage
            except Exception:
                pass
            return resp
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            raise

    def completion_with_tools(
        self,
        messages: List[Dict[str, str]],
        *,
        tools: List[Dict[str, Any]],
        tool_choice: Optional[Dict[str, Any]] = None,
        temperature: float = 0.2,
    ) -> Dict[str, Any]:
        """
        Send a tool-calling request to the configured LLM and return the raw response.
        """
        settings = self._active_settings()
        kwargs: Dict[str, Any] = {
            "model": settings["model"],
            "messages": messages,
            "temperature": temperature,
            "tools": tools,
        }
        if tool_choice is not None:
            kwargs["tool_choice"] = tool_choice
        if settings.get("api_key"):
            kwargs["api_key"] = settings["api_key"]
        if settings.get("api_base"):
            kwargs["api_base"] = settings["api_base"]

        logger.debug(f"Dispatching tool-call to model={settings['model']} provider={settings['provider']}")
        try:
            return litellm.completion(**kwargs)
        except Exception as e:
            logger.error(f"LLM tool-call failed: {e}")
            raise

    def _extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            message = response["choices"][0]["message"]
        except Exception:
            return []
        if not isinstance(message, dict):
            return []
        tool_calls = message.get("tool_calls") or []
        if not tool_calls and message.get("function_call"):
            tool_calls = [{"function": message.get("function_call")}]
        out: List[Dict[str, Any]] = []
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") if isinstance(call.get("function"), dict) else {}
            name = fn.get("name") or call.get("name")
            args_raw = fn.get("arguments") if fn else call.get("arguments")
            args = None
            if isinstance(args_raw, dict):
                args = args_raw
            elif isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw)
                except Exception as e:
                    raise ToolCallingError(f"Tool call arguments invalid JSON: {e}") from e
            elif args_raw is None:
                args = None
            else:
                args = {"value": args_raw}
            out.append(
                {
                    "id": call.get("id"),
                    "name": name,
                    "arguments": args,
                    "raw_arguments": args_raw,
                }
            )
        return out

    def tool_call(
        self,
        messages: List[Dict[str, str]],
        *,
        tools: List[Dict[str, Any]],
        tool_choice: Optional[Dict[str, Any]] = None,
        temperature: float = 0.2,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Execute a tool-calling request and return (tool_calls, meta).
        """
        settings = self._active_settings()
        response = self.completion_with_tools(
            messages,
            tools=tools,
            tool_choice=tool_choice,
            temperature=temperature,
        )
        tool_calls = self._extract_tool_calls(response)
        if not tool_calls:
            raise ToolCallingNotSupported("No tool calls returned by provider/model")

        usage = self._normalize_usage(response.get("usage"))
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
            "usage": usage,
            "tool_calling": True,
        }
        if cost_usd is not None:
            meta["cost_usd"] = float(cost_usd)
        return tool_calls, meta

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
            try:
                meta["usage"] = self._normalize_usage(meta.get("usage"))
            except Exception:
                pass
            meta.setdefault("provider", settings.get("provider"))
            meta.setdefault("model", settings.get("model"))
            meta["cached"] = True
            meta["cache_key"] = response.get("_cache_key")
            return content, meta

        usage = self._normalize_usage(response.get("usage"))
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
            "usage": usage,
        }
        if response.get("_cached"):
            meta["cached"] = True
            meta["cache_key"] = response.get("_cache_key")
        if cost_usd is not None:
            meta["cost_usd"] = float(cost_usd)
        return content, meta
