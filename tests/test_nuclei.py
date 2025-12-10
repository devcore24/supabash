import unittest
from unittest.mock import MagicMock
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.tools.nuclei import NucleiScanner
from supabash.runner import CommandResult

SAMPLE_NUCLEI_JSONL = """{"template-id": "tech-detect", "info": {"name": "Tech Detect", "severity": "info"}, "type": "http", "host": "https://example.com", "matched-at": "https://example.com", "ip": "1.2.3.4"}
{"template-id": "cve-2021-1234", "info": {"name": "Example CVE", "severity": "critical", "description": "Bad vuln"}, "type": "http", "host": "https://example.com", "matched-at": "https://example.com/vuln"}
"""

class TestNucleiScanner(unittest.TestCase):
    def setUp(self):
        self.mock_runner = MagicMock()
        self.scanner = NucleiScanner(runner=self.mock_runner)

    def test_parse_json(self):
        findings = self.scanner._parse_json(SAMPLE_NUCLEI_JSONL)
        self.assertEqual(len(findings), 2)
        
        f1 = findings[0]
        self.assertEqual(f1["id"], "tech-detect")
        self.assertEqual(f1["severity"], "info")
        
        f2 = findings[1]
        self.assertEqual(f2["id"], "cve-2021-1234")
        self.assertEqual(f2["severity"], "critical")
        self.assertEqual(f2["description"], "Bad vuln")

    def test_scan_command(self):
        self.mock_runner.run.return_value = CommandResult(
            command="", return_code=0, stdout="", stderr="", success=True
        )

        self.scanner.scan("example.com", templates="cves")

        self.mock_runner.run.assert_called_once()
        args, _ = self.mock_runner.run.call_args
        command = args[0]
        
        self.assertEqual(command[0], "nuclei")
        self.assertIn("-target", command)
        self.assertIn("example.com", command)
        self.assertIn("-t", command)
        self.assertIn("cves", command)
        self.assertIn("-json", command)

if __name__ == '__main__':
    unittest.main()
