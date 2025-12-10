import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.rustscan import RustscanScanner
from supabash.runner import CommandResult

SAMPLE_GREP = """
# Nmap 7.94SVN scan initiated Tue Jan  1 00:00:00 2025 as: nmap -oG - -p 22,80 -oG - 192.168.0.1
Host: 192.168.0.1 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
# Nmap done at Tue Jan  1 00:00:00 2025 -- 1 IP address (1 host up) scanned in 1.23 seconds
"""

class TestRustscanScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = RustscanScanner(runner=self.mock_runner)

    def test_parse_greppable(self):
        parsed = self.scanner._parse_greppable(SAMPLE_GREP)
        hosts = parsed["hosts"]
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host["ip"], "192.168.0.1")
        ports = sorted(host["ports"], key=lambda p: p["port"])
        self.assertEqual(ports[0]["port"], 22)
        self.assertEqual(ports[0]["service"], "ssh")
        self.assertEqual(ports[1]["port"], 80)
        self.assertEqual(ports[1]["service"], "http")

    def test_scan_command_construction(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_GREP, stderr="", success=True
        )
        self.scanner.scan("10.0.0.5", ports="1-1024", batch=1000)
        self.mock_runner.run.assert_called_once()
        args, kwargs = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "rustscan")
        self.assertIn("-a", cmd)
        self.assertIn("10.0.0.5", cmd)
        self.assertIn("-r", cmd)
        self.assertIn("1-1024", cmd)
        self.assertIn("-b", cmd)
        self.assertIn("--", cmd)  # delimiter before nmap args
        self.assertIn("-oG", cmd)

    def test_scan_failure(self):
        self.mock_runner.run.return_value = CommandResult(
            command="rustscan", return_code=1, stdout="", stderr="error", success=False
        )
        result = self.scanner.scan("bad")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "error")

if __name__ == '__main__':
    unittest.main()
