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
