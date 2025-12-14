import unittest

from supabash.slash_parse import normalize_target_token


class TestSlashParse(unittest.TestCase):
    def test_normalize_target_token_plain(self):
        self.assertEqual(normalize_target_token("localhost"), "localhost")

    def test_normalize_target_token_target_equals(self):
        self.assertEqual(normalize_target_token("target=localhost"), "localhost")

    def test_normalize_target_token_host_equals(self):
        self.assertEqual(normalize_target_token("host=10.0.0.1"), "10.0.0.1")

    def test_normalize_target_token_url_equals(self):
        self.assertEqual(normalize_target_token("url=http://127.0.0.1"), "http://127.0.0.1")


if __name__ == "__main__":
    unittest.main()

