import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.sqlmap import SqlmapScanner
from supabash.runner import CommandResult
from tests.test_artifacts import artifacts_dir

SAMPLE_OUT = """
[INFO] GET parameter 'id' appears to be 'UNION query' injectable
[INFO] GET parameter 'id' appears to be 'error-based' injectable
"""


class TestSqlmapScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = SqlmapScanner(runner=self.mock_runner)

    def test_parse_output(self):
        findings = self.scanner._parse_output(SAMPLE_OUT)
        self.assertEqual(len(findings), 2)
        self.assertIn("UNION query", findings[0]["detail"])

    def test_scan_command_construction(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_OUT, stderr="", success=True
        )
        out_dir = str(artifacts_dir() / "sqlmap-out")
        self.scanner.scan("http://example.com/?id=1", arguments="--risk=1", output_dir=out_dir)
        self.mock_runner.run.assert_called_once()
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "sqlmap")
        self.assertIn("-u", cmd)
        self.assertIn("http://example.com/?id=1", cmd)
        self.assertIn("--risk=1", cmd)
        self.assertIn(f"--output-dir={out_dir}", cmd)

    def test_scan_failure(self):
        self.mock_runner.run.return_value = CommandResult(
            command="sqlmap", return_code=1, stdout="", stderr="error", success=False
        )
        result = self.scanner.scan("bad")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "error")


if __name__ == '__main__':
    unittest.main()
