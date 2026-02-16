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
        suggested = [str(x) for x in (res.get("suggested_commands") or [])]
        self.assertIn("/scan 10.0.0.1", suggested)
        self.assertTrue(all("--yes" not in x for x in suggested))
        fake_llm.chat_with_meta.assert_called_once()
        sent_messages = fake_llm.chat_with_meta.call_args[0][0]
        # Ensure clarifier context advertises current slash command surface.
        self.assertTrue(any("/ai-audit" in str(m.get("content", "")) for m in sent_messages if isinstance(m, dict)))

    def test_clarify_goal_normalizes_ai_audit_key_value_syntax(self):
        fake_llm = MagicMock()
        fake_llm.chat_with_meta.return_value = (
            json.dumps(
                {
                    "questions": ["q1"],
                    "suggested_commands": [
                        "/ai-audit target=localhost standard=soc2 mode=normal --yes",
                        "/details last_run=true",
                        "/summary last_run=true",
                    ],
                    "notes": "n",
                    "safety": ["s"],
                }
            ),
            {"usage": {"total_tokens": 8}, "cost_usd": 0.0},
        )
        session = ChatSession(scanners={}, llm=fake_llm)
        res = session.clarify_goal("run ai audit")
        suggested = [str(x) for x in (res.get("suggested_commands") or [])]
        self.assertIn("/ai-audit localhost --compliance soc2 --mode normal", suggested)
        self.assertIn("/details", suggested)
        self.assertIn("/summary", suggested)
        self.assertTrue(all("--yes" not in x for x in suggested))

    def test_clarify_goal_normalizes_light_mode_to_supported_audit_mode(self):
        fake_llm = MagicMock()
        fake_llm.chat_with_meta.return_value = (
            json.dumps(
                {
                    "questions": ["q1"],
                    "suggested_commands": [
                        "/audit localhost --mode light",
                    ],
                    "notes": "n",
                    "safety": ["s"],
                }
            ),
            {"usage": {"total_tokens": 7}, "cost_usd": 0.0},
        )
        session = ChatSession(scanners={}, llm=fake_llm)
        res = session.clarify_goal("run normal audit")
        suggested = [str(x) for x in (res.get("suggested_commands") or [])]
        self.assertIn("/audit localhost --mode stealth", suggested)

    def test_clarify_goal_fallback_on_bad_json(self):
        fake_llm = MagicMock()
        fake_llm.chat_with_meta.return_value = ("not json", {"usage": {}})
        session = ChatSession(scanners={}, llm=fake_llm)
        res = session.clarify_goal("test goal")
        self.assertIn("questions", res)
        self.assertTrue(res["questions"])
        suggested = [str(x) for x in (res.get("suggested_commands") or [])]
        self.assertTrue(any("/ai-audit" in x for x in suggested))

    def test_clarify_goal_fallback_when_llm_disabled_prefers_ai_audit_command(self):
        class DummyConfig:
            config = {"llm": {"enabled": False}}

        session = ChatSession(scanners={}, llm=MagicMock(), config_manager=DummyConfig())
        res = session.clarify_goal("run an ai audit on staging")
        suggested = [str(x) for x in (res.get("suggested_commands") or [])]
        self.assertTrue(any("/ai-audit" in x for x in suggested))


if __name__ == "__main__":
    unittest.main()
