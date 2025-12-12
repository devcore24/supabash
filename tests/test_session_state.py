import tempfile
import unittest
from pathlib import Path

from supabash.chat import ChatSession


class TestSessionState(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "chat_state.json"
            s1 = ChatSession(scanners={}, llm=None, config_manager=None)
            s1.last_result_kind = "audit"
            s1.last_scan_tool = "nmap"
            s1.last_scan_result = {"success": True, "scan_data": {"hosts": []}}
            s1.last_audit_report = {"target": "t", "results": [], "findings": []}
            s1.last_llm_meta = {"provider": "openai", "model": "gpt-4"}
            s1.last_clarifier = {"questions": ["q"]}

            saved = s1.save_state(path)
            self.assertTrue(saved["success"])

            s2 = ChatSession(scanners={}, llm=None, config_manager=None)
            loaded = s2.load_state(path)
            self.assertTrue(loaded["success"])
            self.assertEqual(s2.last_result_kind, "audit")
            self.assertEqual(s2.last_scan_tool, "nmap")
            self.assertEqual(s2.last_audit_report["target"], "t")


if __name__ == "__main__":
    unittest.main()

