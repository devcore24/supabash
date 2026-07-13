import unittest

from supabash.audit import AuditOrchestrator
from supabash.finding_identity import finding_dedup_key


class TestFindingIdentity(unittest.TestCase):
    def test_audit_and_shared_dedup_contract_match(self):
        finding = {
            "tool": "nuclei",
            "severity": "HIGH",
            "title": "Configuration exposed",
            "evidence": "http://localhost:9090/api/v1/status/config",
        }
        orchestrator = AuditOrchestrator(scanners={"nmap": object()})
        self.assertEqual(orchestrator._finding_dedup_key(finding), finding_dedup_key(finding))

    def test_explicit_dedup_key_is_authoritative_for_benchmark_reports(self):
        first = {"dedup_key": "stable-key", "evidence": "first corroboration"}
        second = {"dedup_key": "stable-key", "evidence": "second corroboration"}
        self.assertEqual(finding_dedup_key(first), finding_dedup_key(second))


if __name__ == "__main__":
    unittest.main()
