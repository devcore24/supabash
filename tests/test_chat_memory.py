import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from supabash.chat import ChatSession


class TestChatMemory(unittest.TestCase):
    def test_redacts_secrets_in_chat_history(self):
        session = ChatSession(scanners={}, llm=None, config_manager=None)
        session.add_message("user", "my key is sk-12345678901234567890")
        saved = session.messages[-1]["content"]
        self.assertIn("sk-***REDACTED***", saved)
        self.assertNotIn("sk-1234567890", saved)

        session.add_message("user", "Authorization: Bearer abc.def.ghi")
        saved2 = session.messages[-1]["content"]
        self.assertIn("Authorization: Bearer ***REDACTED***", saved2)

    def test_state_persists_messages_and_summary(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "chat_state.json"
            s1 = ChatSession(scanners={}, llm=None, config_manager=None)
            s1.add_message("user", "hello")
            s1.conversation_summary = "summary"
            saved = s1.save_state(path)
            self.assertTrue(saved["success"])

            s2 = ChatSession(scanners={}, llm=None, config_manager=None)
            loaded = s2.load_state(path)
            self.assertTrue(loaded["success"])
            self.assertEqual(s2.conversation_summary, "summary")
            self.assertTrue(s2.messages)

    def test_llm_calls_include_history_and_context(self):
        fake_llm = MagicMock()
        fake_llm.chat_with_meta.return_value = (
            json.dumps({"questions": ["q"], "suggested_commands": ["/scan localhost"], "notes": "", "safety": []}),
            {"usage": {"total_tokens": 5}},
        )
        fake_llm.context_window_usage.return_value = {"estimated_prompt_tokens": 10, "max_input_tokens": 100, "context_usage_pct": 10.0}

        session = ChatSession(scanners={}, llm=fake_llm, config_manager=None)
        session.conversation_summary = "Target is localhost"
        session.add_message("user", "first question")
        session.add_message("assistant", "first answer", meta={"source": "llm"})

        session.clarify_goal("second question")
        fake_llm.chat_with_meta.assert_called_once()

        sent_messages = fake_llm.chat_with_meta.call_args[0][0]
        self.assertTrue(any(m.get("role") == "system" and "Conversation summary" in m.get("content", "") for m in sent_messages))
        self.assertTrue(any(m.get("role") == "system" and "Session context" in m.get("content", "") for m in sent_messages))
        self.assertTrue(any(m.get("role") == "user" and "first question" in m.get("content", "") for m in sent_messages))


if __name__ == "__main__":
    unittest.main()

