import unittest

from supabash.safety import is_allowed_target, is_public_ip_target


class TestSafety(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(is_allowed_target("localhost", ["localhost"]))

    def test_cidr_match(self):
        self.assertTrue(is_allowed_target("10.0.0.5", ["10.0.0.0/24"]))
        self.assertFalse(is_allowed_target("10.0.1.5", ["10.0.0.0/24"]))

    def test_url_target_matches_cidr(self):
        self.assertTrue(is_allowed_target("http://10.0.0.5:8080", ["10.0.0.0/24"]))

    def test_wildcard_hostname(self):
        self.assertTrue(is_allowed_target("app.corp.local", ["*.corp.local"]))
        self.assertFalse(is_allowed_target("corp.local", ["*.corp.local"]))

    def test_non_allowed(self):
        self.assertFalse(is_allowed_target("example.com", ["localhost"]))

    def test_public_ip_detection(self):
        self.assertTrue(is_public_ip_target("8.8.8.8"))
        self.assertTrue(is_public_ip_target("http://8.8.8.8:8080"))
        self.assertFalse(is_public_ip_target("10.0.0.1"))
        self.assertFalse(is_public_ip_target("example.com"))


if __name__ == "__main__":
    unittest.main()
