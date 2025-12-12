import json
import unittest
from unittest.mock import MagicMock

from supabash.chat import ChatSession


class TestChatClarifier(unittest.TestCase):
    def test_clarify_goal_uses_llm_when_available(self):
        fake_llm = MagicMock()
        fake_llm.chat_with_meta.return_value = (
            json.dumps(
                {
                    "questions": ["q1"],
                    "suggested_commands": ["supabash scan 10.0.0.1 --yes"],
                    "notes": "n",
                    "safety": ["s"],
                }
            ),
            {"usage": {"total_tokens": 5}, "cost_usd": 0.0},
        )
        session = ChatSession(scanners={}, llm=fake_llm)
        res = session.clarify_goal("test goal")
        self.assertEqual(res["questions"], ["q1"])
        fake_llm.chat_with_meta.assert_called_once()

    def test_clarify_goal_fallback_on_bad_json(self):
        fake_llm = MagicMock()
        fake_llm.chat_with_meta.return_value = ("not json", {"usage": {}})
        session = ChatSession(scanners={}, llm=fake_llm)
        res = session.clarify_goal("test goal")
        self.assertIn("questions", res)
        self.assertTrue(res["questions"])


if __name__ == "__main__":
    unittest.main()

