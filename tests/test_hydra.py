import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.hydra import HydraRunner
from supabash.runner import CommandResult


class TestHydraRunner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.hydra = HydraRunner(runner=self.mock_runner)

    def test_command_construction_defaults(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="OK", stderr="", success=True
        )
        self.hydra.run("127.0.0.1", "ssh", "users.txt", "pass.txt")
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "hydra")
        self.assertIn("-L", cmd)
        self.assertIn("users.txt", cmd)
        self.assertIn("-P", cmd)
        self.assertIn("pass.txt", cmd)
        self.assertIn("ssh://127.0.0.1", cmd)

    def test_command_construction_inline_creds(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="OK", stderr="", success=True
        )
        self.hydra.run("10.0.0.1:2222", "ssh", "admin", "hunter2", options="-I")
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertIn("-l", cmd)
        self.assertIn("admin", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("hunter2", cmd)
        self.assertIn("-I", cmd)
        self.assertIn("ssh://10.0.0.1:2222", cmd)

    def test_failure(self):
        self.mock_runner.run.return_value = CommandResult(
            command="hydra", return_code=1, stdout="", stderr="error", success=False
        )
        result = self.hydra.run("x", "ssh", "u", "p")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "error")


if __name__ == '__main__':
    unittest.main()
