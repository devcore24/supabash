import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tool_settings import get_tool_timeout_seconds, resolve_timeout_seconds


class TestToolSettings(unittest.TestCase):
    def test_get_tool_timeout_seconds_supports_dash_underscore_variants(self):
        cfg = {"tools": {"enum4linux_ng": {"enabled": True, "timeout_seconds": 123}}}
        self.assertEqual(get_tool_timeout_seconds(cfg, "enum4linux-ng"), 123)

    def test_resolve_timeout_seconds_default_when_missing(self):
        self.assertEqual(resolve_timeout_seconds(None, default=60), 60)

    def test_resolve_timeout_seconds_disables_when_zero(self):
        self.assertIsNone(resolve_timeout_seconds(0, default=60))

    def test_resolve_timeout_seconds_parses_strings(self):
        self.assertEqual(resolve_timeout_seconds("15", default=60), 15)


if __name__ == "__main__":
    unittest.main()

