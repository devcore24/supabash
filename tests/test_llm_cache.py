import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from supabash.llm import LLMClient


class DummyConfig:
    def __init__(self, cache_dir: Path):
        self.config = {
            "llm": {
                "provider": "openai",
                "openai": {"api_key": "sk-test", "model": "gpt-4"},
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
                "cache_ttl_seconds": 3600,
                "cache_max_entries": 100,
            }
        }


class TestLLMCache(unittest.TestCase):
    def test_llm_cache_avoids_duplicate_completion_calls(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td)
            client = LLMClient(config=DummyConfig(cache_dir))
            messages = [{"role": "user", "content": "hello"}]

            with patch("supabash.llm.litellm.completion") as mock_completion, patch("supabash.llm.litellm.completion_cost") as mock_cost:
                mock_completion.return_value = {
                    "choices": [{"message": {"content": "hi"}}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                }
                mock_cost.return_value = 0.0001

                c1, m1 = client.chat_with_meta(messages)
                c2, m2 = client.chat_with_meta(messages)

                self.assertEqual(c1, "hi")
                self.assertEqual(c2, "hi")
                self.assertEqual(mock_completion.call_count, 1)
                self.assertFalse(m1.get("cached", False))
                self.assertTrue(m2.get("cached", False))

            # cache file should exist
            files = list(cache_dir.glob("*.json"))
            self.assertTrue(files)
            data = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertIn("content", data)
            self.assertEqual(data["content"], "hi")


if __name__ == "__main__":
    unittest.main()

