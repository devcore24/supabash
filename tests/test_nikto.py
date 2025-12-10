import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.nikto import NiktoScanner
from supabash.runner import CommandResult

SAMPLE_NIKTO_XML = """
<niktoscan hoststest="0" options="-h localhost -p 80 -Format xml -o -" version="2.1.6" scanstart="Fri Jun 11 12:34:56 2021" scanend="Fri Jun 11 12:35:56 2021" niktostart="Fri Jun 11 12:34:56 2021" niktoend="Fri Jun 11 12:35:56 2021">
<scandetails targetip="127.0.0.1" targethostname="localhost" targetport="80" sitename="http://localhost:80/" siteip="127.0.0.1" hostheader="localhost" errors="0" checks="100">
<item id="999999" osvdbid="0" oslink="http://osvdb.org/0" method="GET">
<description>The anti-clickjacking X-Frame-Options header is not present.</description>
<uri>/</uri>
<namelink>http://localhost:80/</namelink>
<iplink>http://127.0.0.1:80/</iplink>
</item>
<item id="123456" osvdbid="123" method="POST">
<description>Server leaks version info via headers.</description>
<uri>/login</uri>
</item>
</scandetails>
</niktoscan>
"""

class TestNiktoScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = NiktoScanner(runner=self.mock_runner)

    def test_parse_xml(self):
        result = self.scanner._parse_xml(SAMPLE_NIKTO_XML)
        
        self.assertEqual(result["target_ip"], "127.0.0.1")
        self.assertEqual(result["target_port"], "80")
        
        findings = result["findings"]
        self.assertEqual(len(findings), 2)
        
        f1 = findings[0]
        self.assertIn("anti-clickjacking", f1["description"])
        self.assertEqual(f1["uri"], "/")
        
        f2 = findings[1]
        self.assertEqual(f2["method"], "POST")

    def test_scan_command_construction(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout=SAMPLE_NIKTO_XML, stderr="", success=True
        )

        self.scanner.scan("example.com", port=8080)

        self.mock_runner.run.assert_called_once()
        args, kwargs = self.mock_runner.run.call_args
        command = args[0]
        
        # Check command structure
        self.assertEqual(command[0], "nikto")
        self.assertIn("-h", command)
        self.assertIn("example.com", command)
        self.assertIn("-p", command)
        self.assertIn("8080", command)
        self.assertIn("-Format", command)
        self.assertIn("xml", command)

if __name__ == '__main__':
    unittest.main()
