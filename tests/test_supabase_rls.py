import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.supabase_rls import SupabaseRLSChecker


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class TestSupabaseRLSChecker(unittest.TestCase):
    def test_allows_public_access_flags_risk(self):
        session = MagicMock()
        session.get.return_value = FakeResponse(200)
        checker = SupabaseRLSChecker(session=session)
        result = checker.check("http://example.com")
        self.assertTrue(result["success"])
        self.assertFalse(result["rls_enabled"])
        self.assertTrue(result["risk"])
        self.assertEqual(result["status"], 200)

    def test_unauthorized_marks_rls_enabled(self):
        session = MagicMock()
        session.get.return_value = FakeResponse(401)
        checker = SupabaseRLSChecker(session=session)
        result = checker.check("http://example.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["rls_enabled"])
        self.assertFalse(result["risk"])

    def test_failure(self):
        session = MagicMock()
        session.get.side_effect = Exception("boom")
        checker = SupabaseRLSChecker(session=session)
        result = checker.check("http://example.com")
        self.assertFalse(result["success"])
        self.assertIn("boom", result["error"])


if __name__ == '__main__':
    unittest.main()
