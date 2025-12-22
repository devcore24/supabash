import unittest
from unittest.mock import MagicMock
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.tools.aircrack_ng import AircrackNgScanner
from supabash.runner import CommandResult


SAMPLE_CSV = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2025-01-01 00:00:00, 2025-01-01 00:00:01, 6, 54, OPN, , , -30, 1, 0, 0. 0. 0. 0, 6, OpenNet,
11:22:33:44:55:66, 2025-01-01 00:00:00, 2025-01-01 00:00:01, 11, 54, WEP, WEP, OPN, -40, 1, 0, 0. 0. 0. 0, 7, WEPNet,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
66:55:44:33:22:11, 2025-01-01 00:00:00, 2025-01-01 00:00:01, -20, 5, AA:BB:CC:DD:EE:FF, OpenNet
"""


class TestAircrackNgScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = AircrackNgScanner(runner=self.mock_runner)

    def test_scan_parses_csv(self):
        self.mock_runner.run.return_value = CommandResult(
            command="airodump-ng", return_code=0, stdout="", stderr="", success=True
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "aircrack-01.csv"
            csv_path.write_text(SAMPLE_CSV, encoding="utf-8")
            result = self.scanner.scan(interface="wlan0mon", output_dir=tmpdir)

        self.assertTrue(result["success"])
        scan_data = result["scan_data"]
        self.assertEqual(scan_data["total_access_points"], 2)
        self.assertEqual(scan_data["total_clients"], 1)
        securities = {ap.get("security") for ap in scan_data["access_points"]}
        self.assertIn("OPEN", securities)
        self.assertIn("WEP", securities)
        args, _ = self.mock_runner.run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "airodump-ng")
        self.assertIn("wlan0mon", cmd)

    def test_airmon_uses_monitor_iface(self):
        start_out = "monitor mode vif enabled for [phy0] on [wlan0mon]"
        self.mock_runner.run.side_effect = [
            CommandResult(command="airmon-ng start wlan0", return_code=0, stdout=start_out, stderr="", success=True),
            CommandResult(command="airodump-ng", return_code=0, stdout="", stderr="", success=True),
            CommandResult(command="airmon-ng stop wlan0mon", return_code=0, stdout="", stderr="", success=True),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "aircrack-01.csv"
            csv_path.write_text(SAMPLE_CSV, encoding="utf-8")
            result = self.scanner.scan(interface="wlan0", output_dir=tmpdir, airmon=True)

        self.assertTrue(result["success"])
        call_cmds = [call[0][0] for call in self.mock_runner.run.call_args_list]
        self.assertEqual(call_cmds[0][0], "airmon-ng")
        self.assertEqual(call_cmds[1][0], "airodump-ng")
        self.assertEqual(call_cmds[2][0], "airmon-ng")
        self.assertEqual(call_cmds[1][-1], "wlan0mon")


if __name__ == "__main__":
    unittest.main()
