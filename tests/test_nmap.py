import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.nmap import NmapScanner
from supabash.runner import CommandResult

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX - localhost" start="1623456789" startstr="Fri Jun 11 12:34:56 2021" version="7.91" xmloutputversion="1.05">
<host starttime="1623456789" endtime="1623456790">
<status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="user"/>
<hostname name="localhost.localdomain" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset" reason_ttl="64"/><service name="http" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 4.15 - 5.6" accuracy="100" line="67069"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="100"><cpe>cpe:/o:linux:linux_kernel:4</cpe><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os>
</host>
</nmaprun>
"""

class TestNmapScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = NmapScanner(runner=self.mock_runner)

    def test_parse_xml(self):
        """Test that the XML parser correctly extracts host, port, and service info."""
        result = self.scanner._parse_xml(SAMPLE_NMAP_XML)
        
        self.assertIn("hosts", result)
        hosts = result["hosts"]
        self.assertEqual(len(hosts), 1)
        
        host = hosts[0]
        self.assertEqual(host["ip"], "127.0.0.1")
        self.assertIn("localhost", host["hostnames"])
        
        # Check ports
        # Expecting only 1 open port (22), port 80 is closed in sample
        self.assertEqual(len(host["ports"]), 1)
        
        ssh_port = host["ports"][0]
        self.assertEqual(ssh_port["port"], 22)
        self.assertEqual(ssh_port["service"], "ssh")
        self.assertEqual(ssh_port["product"], "OpenSSH")
        self.assertEqual(ssh_port["version"], "8.2p1 Ubuntu")

        # Check OS
        self.assertEqual(host["os"][0]["name"], "Linux 4.15 - 5.6")

    def test_scan_command_construction(self):
        """Test that the scan method constructs the correct command."""
        # Setup mock return
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_NMAP_XML, stderr="", success=True
        )

        self.scanner.scan("192.168.1.1", ports="80,443", arguments="-sV")

        # Verify call arguments
        # Expected: ['nmap', '192.168.1.1', '-oX', '-', '-p', '80,443', '-sV']
        self.mock_runner.run.assert_called_once()
        args, kwargs = self.mock_runner.run.call_args
        command_list = args[0]
        
        self.assertEqual(command_list[0], "nmap")
        self.assertEqual(command_list[1], "192.168.1.1")
        self.assertIn("-oX", command_list)
        self.assertIn("-", command_list) # Ensures stdout output
        self.assertIn("-p", command_list)
        self.assertIn("80,443", command_list)

    def test_scan_failure(self):
        """Test handling of nmap failure."""
        self.mock_runner.run.return_value = CommandResult(
            command="nmap", return_code=1, stdout="", stderr="Failed to resolve host", success=False
        )

        result = self.scanner.scan("invalid_host")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Failed to resolve host")

if __name__ == '__main__':
    unittest.main()
