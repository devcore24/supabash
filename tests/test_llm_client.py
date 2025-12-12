import unittest
from unittest.mock import patch
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.llm import LLMClient


class DummyConfig:
    def __init__(self, provider="openai", model="gpt-4", api_key="sk-test", api_base=None):
        llm_cfg = {
            "provider": provider,
            provider: {
                "api_key": api_key,
                "model": model,
            }
        }
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

    def test_missing_key_raises(self):
        cfg = DummyConfig(api_key="YOUR_KEY_HERE")
        client = LLMClient(config=cfg)
        with self.assertRaises(ValueError):
            client.chat([{"role": "user", "content": "hi"}])

    def test_missing_model_raises(self):
        cfg = DummyConfig(model=None)
        client = LLMClient(config=cfg)
        with self.assertRaises(ValueError):
            client.chat([{"role": "user", "content": "hi"}])


if __name__ == "__main__":
    unittest.main()
