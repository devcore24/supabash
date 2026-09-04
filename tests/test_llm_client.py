import unittest
from unittest.mock import patch
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.llm import LLMClient


class DummyConfig:
    def __init__(
        self,
        provider="openai",
        model="gpt-4",
        api_key="sk-test",
        api_base=None,
        api_key_env=None,
    ):
        llm_cfg = {
            "provider": provider,
            provider: {
                "api_key": api_key,
                "model": model,
            }
        }
        if api_key_env is not None:
            llm_cfg[provider]["api_key_env"] = api_key_env
        if api_base:
            llm_cfg[provider]["api_base"] = api_base
        llm_cfg.setdefault("cache_enabled", False)
        self.config = {"llm": llm_cfg}


class TestLLMClient(unittest.TestCase):
    def test_chat_success(self):
        cfg = DummyConfig()
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]

        with patch("supabash.llm.litellm.completion") as mock_completion:
            mock_completion.return_value = {"choices": [{"message": {"content": "hi"}}]}
            content = client.chat(messages)
            self.assertEqual(content, "hi")
            args, kwargs = mock_completion.call_args
            self.assertEqual(kwargs["model"], "gpt-4")
            self.assertEqual(kwargs["api_key"], "sk-test")

    def test_chat_with_meta_includes_usage_and_cost_when_available(self):
        cfg = DummyConfig()
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]

        with patch("supabash.llm.litellm.completion") as mock_completion, patch("supabash.llm.litellm.completion_cost") as mock_cost:
            mock_completion.return_value = {
                "choices": [{"message": {"content": "hi"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            }
            mock_cost.return_value = 0.000123
            content, meta = client.chat_with_meta(messages)
            self.assertEqual(content, "hi")
            self.assertEqual(meta["model"], "gpt-4")
            self.assertIn("usage", meta)
            self.assertEqual(meta["usage"]["total_tokens"], 5)
            self.assertAlmostEqual(meta["cost_usd"], 0.000123, places=9)

    def test_chat_with_meta_normalizes_usage_object(self):
        class Usage:
            def __init__(self):
                self.prompt_tokens = 3
                self.completion_tokens = 2
                self.total_tokens = 5

        cfg = DummyConfig()
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]

        with patch("supabash.llm.litellm.completion") as mock_completion:
            mock_completion.return_value = {
                "choices": [{"message": {"content": "hi"}}],
                "usage": Usage(),
            }
            content, meta = client.chat_with_meta(messages)
            self.assertEqual(content, "hi")
            self.assertIsInstance(meta.get("usage"), dict)
            self.assertEqual(meta["usage"]["total_tokens"], 5)

    def test_missing_key_raises(self):
        cfg = DummyConfig(api_key="YOUR_KEY_HERE")
        client = LLMClient(config=cfg)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                client.chat([{"role": "user", "content": "hi"}])

    def test_provider_default_environment_keys(self):
        defaults = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        for provider, env_name in defaults.items():
            with self.subTest(provider=provider):
                cfg = DummyConfig(provider=provider, api_key="")
                with patch.dict(os.environ, {env_name: f"{provider}-secret"}, clear=True):
                    settings = LLMClient(config=cfg)._active_settings()
                self.assertEqual(settings["api_key"], f"{provider}-secret")

    def test_configured_api_key_env_is_used_for_custom_provider(self):
        cfg = DummyConfig(
            provider="custom",
            api_key="YOUR_CUSTOM_KEY",
            api_key_env="SUPABASH_TEST_CUSTOM_KEY",
        )
        with patch.dict(
            os.environ, {"SUPABASH_TEST_CUSTOM_KEY": "custom-secret"}, clear=True
        ):
            settings = LLMClient(config=cfg)._active_settings()
        self.assertEqual(settings["api_key"], "custom-secret")

    def test_inline_api_key_takes_precedence_over_environment(self):
        cfg = DummyConfig(api_key="inline-secret", api_key_env="SUPABASH_TEST_LLM_KEY")
        with patch.dict(
            os.environ, {"SUPABASH_TEST_LLM_KEY": "environment-secret"}, clear=True
        ):
            settings = LLMClient(config=cfg)._active_settings()
        self.assertEqual(settings["api_key"], "inline-secret")

    def test_legacy_env_reference_is_resolved_not_sent_literally(self):
        cfg = DummyConfig(provider="custom", api_key="${SUPABASH_TEST_LEGACY_KEY}")
        with patch.dict(
            os.environ, {"SUPABASH_TEST_LEGACY_KEY": "legacy-secret"}, clear=True
        ):
            settings = LLMClient(config=cfg)._active_settings()
        self.assertEqual(settings["api_key"], "legacy-secret")

    def test_invalid_api_key_env_fails_without_exposing_environment_value(self):
        cfg = DummyConfig(api_key="", api_key_env="NOT A VALID NAME")
        with patch.dict(os.environ, {"NOT A VALID NAME": "do-not-expose"}, clear=True):
            with self.assertRaisesRegex(ValueError, "environment variable name") as ctx:
                LLMClient(config=cfg)._active_settings()
        self.assertNotIn("do-not-expose", str(ctx.exception))

    def test_placeholder_environment_value_is_rejected(self):
        cfg = DummyConfig(api_key="", api_key_env="SUPABASH_TEST_LLM_KEY")
        with patch.dict(
            os.environ, {"SUPABASH_TEST_LLM_KEY": "YOUR_OPENAI_KEY"}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "SUPABASH_TEST_LLM_KEY"):
                LLMClient(config=cfg)._active_settings()

    def test_ollama_provider_allows_missing_key_and_omits_api_key_param(self):
        cfg = DummyConfig(provider="ollama", model="ollama/llama3.1", api_key=None, api_base="http://localhost:11434")
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]

        with patch("supabash.llm.litellm.completion") as mock_completion:
            mock_completion.return_value = {"choices": [{"message": {"content": "hi"}}]}
            content = client.chat(messages)
            self.assertEqual(content, "hi")
            _, kwargs = mock_completion.call_args
            self.assertEqual(kwargs["model"], "ollama/llama3.1")
            self.assertEqual(kwargs["api_base"], "http://localhost:11434")
            self.assertNotIn("api_key", kwargs)

    def test_lmstudio_provider_allows_missing_key_and_omits_api_key_param(self):
        cfg = DummyConfig(provider="lmstudio", model="local-model", api_key=None, api_base="http://localhost:1234/v1")
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]

        with patch("supabash.llm.litellm.completion") as mock_completion:
            mock_completion.return_value = {"choices": [{"message": {"content": "hi"}}]}
            content = client.chat(messages)
            self.assertEqual(content, "hi")
            _, kwargs = mock_completion.call_args
            self.assertEqual(kwargs["model"], "local-model")
            self.assertEqual(kwargs["api_base"], "http://localhost:1234/v1")
            self.assertNotIn("api_key", kwargs)

    def test_missing_model_raises(self):
        cfg = DummyConfig(model=None)
        client = LLMClient(config=cfg)
        with self.assertRaises(ValueError):
            client.chat([{"role": "user", "content": "hi"}])

    def test_chat_retries_without_temperature_when_model_rejects_it(self):
        cfg = DummyConfig()
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]

        with patch("supabash.llm.litellm.completion") as mock_completion:
            mock_completion.side_effect = [
                RuntimeError("UnsupportedParamsError: temperature is not supported for this model"),
                {"choices": [{"message": {"content": "hi"}}]},
            ]
            content = client.chat(messages)

            self.assertEqual(content, "hi")
            self.assertEqual(mock_completion.call_count, 2)
            first_kwargs = mock_completion.call_args_list[0].kwargs
            second_kwargs = mock_completion.call_args_list[1].kwargs
            self.assertIn("temperature", first_kwargs)
            self.assertNotIn("temperature", second_kwargs)

    def test_completion_with_tools_retries_without_temperature_when_model_rejects_it(self):
        cfg = DummyConfig()
        client = LLMClient(config=cfg)
        messages = [{"role": "user", "content": "hello"}]
        tools = [{"type": "function", "function": {"name": "ping", "parameters": {"type": "object"}}}]

        with patch("supabash.llm.litellm.completion") as mock_completion:
            mock_completion.side_effect = [
                RuntimeError("UnsupportedParamsError: temperature not supported"),
                {
                    "choices": [
                        {
                            "message": {
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "function": {"name": "ping", "arguments": "{}"},
                                    }
                                ]
                            }
                        }
                    ]
                },
            ]
            resp = client.completion_with_tools(messages, tools=tools)

            self.assertIn("choices", resp)
            self.assertEqual(mock_completion.call_count, 2)
            first_kwargs = mock_completion.call_args_list[0].kwargs
            second_kwargs = mock_completion.call_args_list[1].kwargs
            self.assertIn("temperature", first_kwargs)
            self.assertNotIn("temperature", second_kwargs)


if __name__ == "__main__":
    unittest.main()
