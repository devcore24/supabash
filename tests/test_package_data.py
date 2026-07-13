import unittest
from importlib import resources


class TestPackageData(unittest.TestCase):
    def test_common_wordlist_is_packaged(self):
        wordlist = resources.files("supabash").joinpath("data", "wordlists", "common.txt")
        self.assertTrue(wordlist.is_file())
        self.assertTrue(wordlist.read_text(encoding="utf-8").strip())


if __name__ == "__main__":
    unittest.main()
