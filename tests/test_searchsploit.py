import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.searchsploit import SearchsploitScanner
from supabash.runner import CommandResult


class TestSearchsploitScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = SearchsploitScanner(runner=self.mock_runner)

    def test_parses_json_results(self):
        stdout = """
        {
          "RESULTS_EXPLOIT": {
            "exploits": [
              {"Title": "Apache 2.4.x - Example Exploit", "Path": "exploits/linux/webapps/12345.txt"}
            ]
          },
          "RESULTS_SHELLCODE": {
            "shellcodes": [
              {"Title": "Linux x86 - Example Shellcode", "Path": "shellcodes/linux_x86/99999.txt"}
            ]
          }
        }
        """.strip()
        self.mock_runner.run.return_value = CommandResult(
            command="searchsploit ...",
            return_code=0,
            stdout=stdout,
            stderr="",
            success=True,
        )

        out = self.scanner.search("apache 2.4")
        self.assertTrue(out["success"])
        self.assertEqual(out["query"], "apache 2.4")
        self.assertEqual(len(out["findings"]), 2)
        kinds = {f["kind"] for f in out["findings"]}
        self.assertIn("exploit", kinds)
        self.assertIn("shellcode", kinds)

    def test_command_contains_expected_flags(self):
        self.mock_runner.run.return_value = CommandResult(
            command="",
            return_code=0,
            stdout="{}",
            stderr="",
            success=True,
        )
        self.scanner.search("postgresql 9.6")
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "searchsploit")
        self.assertIn("-j", cmd)
        self.assertIn("postgresql 9.6", cmd)

    def test_rejects_empty_query(self):
        out = self.scanner.search("   ")
        self.assertFalse(out["success"])


if __name__ == "__main__":
    unittest.main()

