import unittest
import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.chat import ChatSession


class TestChatSession(unittest.TestCase):
    def test_summarize_uses_llm(self):
        fake_llm = MagicMock()
        fake_llm.chat.return_value = "summary"
        session = ChatSession(scanners={}, llm=fake_llm)
        session.last_scan_result = {"success": True, "scan_data": {"hosts": []}}
        session.last_scan_tool = "nmap"
        summary = session.summarize_findings()
        self.assertEqual(summary, "summary")
        fake_llm.chat.assert_called_once()

    def test_remediate_calls_llm(self):
        fake_llm = MagicMock()
        fake_llm.chat.return_value = "fix"
        session = ChatSession(scanners={}, llm=fake_llm)
        resp = session.remediate("SQLi", "evidence")
        self.assertEqual(resp, "fix")
        fake_llm.chat.assert_called_once()


if __name__ == "__main__":
    unittest.main()
