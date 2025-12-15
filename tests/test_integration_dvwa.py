import os
import shutil
import subprocess
import time
import unittest
from urllib.request import urlopen

from supabash.audit import AuditOrchestrator
from tests.test_artifacts import artifact_path, cleanup_artifact


def _has_bin(name: str) -> bool:
    return shutil.which(name) is not None


class TestIntegrationDVWA(unittest.TestCase):
    @unittest.skipUnless(os.getenv("SUPABASH_INTEGRATION") == "1", "set SUPABASH_INTEGRATION=1 to run")
    def test_audit_against_dvwa(self):
        required = ["docker", "nmap", "whatweb", "nuclei", "gobuster", "sqlmap"]
        missing = [b for b in required if not _has_bin(b)]
        if missing:
            self.skipTest(f"missing binaries: {', '.join(missing)}")

        compose = os.path.join(os.path.dirname(__file__), "..", "docker-compose.integration.yml")
        target = "http://127.0.0.1:3001"

        try:
            subprocess.run(["docker", "compose", "-f", compose, "up", "-d", "dvwa"], check=True, capture_output=True, text=True)

            deadline = time.time() + 90
            last_err = None
            while time.time() < deadline:
                try:
                    with urlopen(target, timeout=2) as resp:
                        if resp.status in (200, 302):
                            break
                except Exception as e:
                    last_err = e
                    time.sleep(1)
            else:
                self.fail(f"DVWA not reachable: {last_err}")

            orch = AuditOrchestrator()
            out = artifact_path("dvwa_audit.json")
            report = orch.run(target, out, mode="normal", nuclei_rate_limit=1, gobuster_threads=5)
            self.assertTrue(out.exists())
            self.assertEqual(report.get("target"), target)
            self.assertIn("results", report)
            self.assertEqual(report.get("web_targets"), [target])
            cleanup_artifact(out)
        finally:
            subprocess.run(["docker", "compose", "-f", compose, "down"], check=False, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()

