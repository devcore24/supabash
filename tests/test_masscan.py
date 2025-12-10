import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.masscan import MasscanScanner
from supabash.runner import CommandResult

SAMPLE_MASSCAN_LIST = """
#masscan
#timestamp 2025-01-01T00:00:00
open tcp 22 192.168.0.10 0.52s
open tcp 80 192.168.0.10 0.53s
open udp 53 192.168.0.20 0.54s
"""

class TestMasscanScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = MasscanScanner(runner=self.mock_runner)

    def test_parse_list_output(self):
        parsed = self.scanner._parse_list_output(SAMPLE_MASSCAN_LIST)
        hosts = parsed["hosts"]
        self.assertEqual(len(hosts), 2)

        host1 = next(h for h in hosts if h["ip"] == "192.168.0.10")
        self.assertEqual(len(host1["ports"]), 2)
        ports = sorted(p["port"] for p in host1["ports"])
        self.assertEqual(ports, [22, 80])

        host2 = next(h for h in hosts if h["ip"] == "192.168.0.20")
        self.assertEqual(host2["ports"][0]["protocol"], "udp")
        self.assertEqual(host2["ports"][0]["port"], 53)

    def test_scan_command_construction(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_MASSCAN_LIST, stderr="", success=True
        )

        self.scanner.scan("10.0.0.0/24", ports="1-100", rate=500)
        self.mock_runner.run.assert_called_once()
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "masscan")
        self.assertIn("-oL", cmd)
        self.assertIn("-", cmd)
        self.assertIn("--rate", cmd)
        self.assertIn("1-100", cmd)
        self.assertIn("10.0.0.0/24", cmd)

    def test_scan_failure(self):
        self.mock_runner.run.return_value = CommandResult(
            command="masscan", return_code=1, stdout="", stderr="failed", success=False
        )
        result = self.scanner.scan("invalid")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "failed")

if __name__ == '__main__':
    unittest.main()
