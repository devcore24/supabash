import sys
import os
from typer.testing import CliRunner
import supabash.__main__ as main_module

runner = CliRunner()

class FakeNmap:
    def __init__(self):
        self.called_with = None
    def scan(self, target, ports=None, arguments=None):
        self.called_with = (target, ports, arguments)
        return {
            "success": True,
            "scan_data": {
                "hosts": [
                    {"ip": target, "hostnames": [], "ports": [{"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.0", "protocol": "tcp"}], "os": []}
                ]
            }
        }

class FakeMasscan:
    def __init__(self):
        self.called_with = None
    def scan(self, target, ports=None, rate=None, arguments=None):
        self.called_with = (target, ports, rate, arguments)
        return {
            "success": True,
            "scan_data": {
                "hosts": [
                    {"ip": target, "ports": [{"port": 80, "state": "open", "protocol": "tcp"}]}
                ]
            }
        }

class FakeRustscan:
    def __init__(self):
        self.called_with = None
    def scan(self, target, ports=None, batch=None, arguments=None):
        self.called_with = (target, ports, batch, arguments)
        return {
            "success": True,
            "scan_data": {
                "hosts": [
                    {"ip": target, "ports": [{"port": 443, "state": "open", "service": "https", "protocol": "tcp"}]}
                ]
            }
        }

def test_scan_default_nmap(monkeypatch):
    fake = FakeNmap()
    monkeypatch.setitem(main_module.SCANNERS, "nmap", lambda: fake)
    result = runner.invoke(main_module.app, ["scan", "1.2.3.4"])
    assert result.exit_code == 0
    assert "Starting fast scan" in result.stdout
    assert fake.called_with == ("1.2.3.4", None, "-sV -O -F")
    assert "22" in result.stdout

def test_scan_masscan(monkeypatch):
    fake = FakeMasscan()
    monkeypatch.setitem(main_module.SCANNERS, "masscan", lambda: fake)
    result = runner.invoke(main_module.app, ["scan", "10.0.0.1", "--scanner", "masscan", "--profile", "full"])
    assert result.exit_code == 0
    assert fake.called_with == ("10.0.0.1", "1-65535", 5000, None)
    assert "80" in result.stdout

def test_scan_rustscan(monkeypatch):
    fake = FakeRustscan()
    monkeypatch.setitem(main_module.SCANNERS, "rustscan", lambda: fake)
    result = runner.invoke(main_module.app, ["scan", "10.0.0.2", "--scanner", "rustscan", "--profile", "stealth"])
    assert result.exit_code == 0
    assert fake.called_with == ("10.0.0.2", "1-1000", 1000, None)
    assert "443" in result.stdout
