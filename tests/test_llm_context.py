import unittest

from supabash.llm_context import prepare_json_payload


class TestLLMContext(unittest.TestCase):
    def test_prepare_json_payload_not_truncated_when_small(self):
        content, truncated = prepare_json_payload({"a": 1, "b": "ok"}, max_chars=1000)
        self.assertFalse(truncated)
        self.assertIn('"a": 1', content)

    def test_prepare_json_payload_truncates_large_payload(self):
        big = {
            "target": "example",
            "stdout": "X" * 20000,
            "items": list(range(10000)),
        }
        content, truncated = prepare_json_payload(big, max_chars=2000)
        self.assertTrue(truncated)
        self.assertLessEqual(len(content), 2000)
        self.assertIn("target", content)
        self.assertIn("truncated", content)

    def test_prepare_json_payload_does_not_fallback_to_minimal_note(self):
        # Regression: if the payload is only slightly too large after an initial shrink,
        # we should keep shrinking (instead of returning a near-empty "payload too large" note).
        obj = {
            "target": "example",
            "items": [{"k": "x" * 200} for _ in range(20)],
        }
        content, truncated = prepare_json_payload(obj, max_chars=2000)
        self.assertTrue(truncated)
        self.assertLessEqual(len(content), 2000)
        self.assertIn("target", content)
        self.assertNotIn("payload too large; truncated aggressively", content)


if __name__ == "__main__":
    unittest.main()
