import unittest
from unittest.mock import patch

from typer.testing import CliRunner
import supabash.__main__ as main_module


runner = CliRunner()


class FakeNmap:
    instance = None

    def __init__(self):
        FakeNmap.instance = self
        self.called_with = None
        self.timeout_seconds = None

    def scan(self, target, ports=None, arguments=None, timeout_seconds=None, **kwargs):
        self.called_with = (target, ports, arguments)
        self.timeout_seconds = timeout_seconds
        return {
            "success": True,
            "scan_data": {
                "hosts": [
                    {
                        "ip": target,
                        "hostnames": [],
                        "ports": [
                            {
                                "port": 22,
                                "state": "open",
                                "service": "ssh",
                                "product": "OpenSSH",
                                "version": "9.0",
                                "protocol": "tcp",
                            }
                        ],
                        "os": [],
                    }
                ]
            },
        }


class FakeMasscan:
    instance = None

    def __init__(self):
        FakeMasscan.instance = self
        self.called_with = None
        self.timeout_seconds = None

    def scan(self, target, ports=None, rate=None, arguments=None, timeout_seconds=None, **kwargs):
        self.called_with = (target, ports, rate, arguments)
        self.timeout_seconds = timeout_seconds
        return {
            "success": True,
            "scan_data": {"hosts": [{"ip": target, "ports": [{"port": 80, "state": "open", "protocol": "tcp"}]}]},
        }


class FakeRustscan:
    instance = None

    def __init__(self):
        FakeRustscan.instance = self
        self.called_with = None
        self.timeout_seconds = None

    def scan(self, target, ports=None, batch=None, arguments=None, timeout_seconds=None, **kwargs):
        self.called_with = (target, ports, batch, arguments)
        self.timeout_seconds = timeout_seconds
        return {
            "success": True,
            "scan_data": {"hosts": [{"ip": target, "ports": [{"port": 443, "state": "open", "service": "https", "protocol": "tcp"}]}]},
        }


class TestScanCLI(unittest.TestCase):
    def test_scan_default_nmap(self):
        with patch.dict(main_module.SCANNERS, {"nmap": FakeNmap}):
            result = runner.invoke(main_module.app, ["scan", "10.0.0.3", "--force", "--yes"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Starting fast scan", result.stdout)
        self.assertEqual(FakeNmap.instance.called_with, ("10.0.0.3", None, "-sV -O -F"))
        self.assertIsNotNone(FakeNmap.instance.timeout_seconds)
        self.assertIn("22", result.stdout)

    def test_scan_blocks_public_ip_by_default(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = False
        with patch.dict(main_module.SCANNERS, {"nmap": FakeNmap}):
            result = runner.invoke(main_module.app, ["scan", "8.8.8.8", "--force", "--yes"])
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Refusing to scan public IP targets", result.stdout)

    def test_scan_allows_public_ip_with_flag(self):
        main_module.config_manager.config.setdefault("core", {})["allow_public_ips"] = False
        with patch.dict(main_module.SCANNERS, {"nmap": FakeNmap}):
            result = runner.invoke(main_module.app, ["scan", "8.8.8.8", "--force", "--yes", "--allow-public"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertEqual(FakeNmap.instance.called_with, ("8.8.8.8", None, "-sV -O -F"))
        self.assertIn("22", result.stdout)

    def test_scan_masscan(self):
        with patch.dict(main_module.SCANNERS, {"masscan": FakeMasscan}):
            result = runner.invoke(
                main_module.app,
                ["scan", "10.0.0.1", "--scanner", "masscan", "--profile", "full", "--force", "--yes"],
            )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertEqual(FakeMasscan.instance.called_with, ("10.0.0.1", "1-65535", 5000, None))
        self.assertIsNotNone(FakeMasscan.instance.timeout_seconds)
        self.assertIn("80", result.stdout)

    def test_scan_rustscan(self):
        with patch.dict(main_module.SCANNERS, {"rustscan": FakeRustscan}):
            result = runner.invoke(
                main_module.app,
                ["scan", "10.0.0.2", "--scanner", "rustscan", "--profile", "stealth", "--force", "--yes"],
            )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertEqual(FakeRustscan.instance.called_with, ("10.0.0.2", "1-1000", 1000, None))
        self.assertIsNotNone(FakeRustscan.instance.timeout_seconds)
        self.assertIn("443", result.stdout)

    def test_scan_uses_timeout_seconds_from_config(self):
        original = main_module.config_manager.config.setdefault("tools", {}).setdefault("nmap", {}).get("timeout_seconds")
        main_module.config_manager.config["tools"]["nmap"]["timeout_seconds"] = 12
        try:
            with patch.dict(main_module.SCANNERS, {"nmap": FakeNmap}):
                result = runner.invoke(main_module.app, ["scan", "10.0.0.9", "--force", "--yes"])
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertEqual(FakeNmap.instance.timeout_seconds, 12)
        finally:
            if original is None:
                main_module.config_manager.config["tools"]["nmap"].pop("timeout_seconds", None)
            else:
                main_module.config_manager.config["tools"]["nmap"]["timeout_seconds"] = original


if __name__ == "__main__":
    unittest.main()
