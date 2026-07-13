import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from supabash.chat import ChatSession
from supabash.session_state import save_state


class TestSessionState(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
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

    def test_state_file_is_replaced_atomically_with_private_permissions(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            path = Path(td) / "chat_state.json"
            path.write_text("{\"old\": true}", encoding="utf-8")
            path.chmod(0o644)

            success, _ = save_state(path, {"message": "private"})

            self.assertTrue(success)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(encoding="utf-8"), "{\"message\": \"private\"}")

    def test_failed_atomic_replace_preserves_existing_state(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            path = Path(td) / "chat_state.json"
            original = "{\"message\": \"existing\"}"
            path.write_text(original, encoding="utf-8")

            with patch("supabash.secure_io.os.replace", side_effect=OSError("replace failed")):
                success, truncated = save_state(path, {"message": "new"})

            self.assertFalse(success)
            self.assertFalse(truncated)
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()

