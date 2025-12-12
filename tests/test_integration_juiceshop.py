import os
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

from supabash.audit import AuditOrchestrator


def _has_bin(name: str) -> bool:
    return shutil.which(name) is not None


class TestIntegrationJuiceShop(unittest.TestCase):
    @unittest.skipUnless(os.getenv("SUPABASH_INTEGRATION") == "1", "set SUPABASH_INTEGRATION=1 to run")
    def test_audit_against_juiceshop(self):
        required = ["docker", "nmap", "whatweb", "nuclei", "gobuster", "sqlmap"]
        missing = [b for b in required if not _has_bin(b)]
        if missing:
            self.skipTest(f"missing binaries: {', '.join(missing)}")

        compose = Path(__file__).resolve().parents[1] / "docker-compose.integration.yml"
        if not compose.exists():
            self.skipTest("missing docker-compose.integration.yml")

        target = "http://127.0.0.1:3000"
        try:
            subprocess.run(["docker", "compose", "-f", str(compose), "up", "-d"], check=True, capture_output=True, text=True)

            # Wait for HTTP to become reachable
            deadline = time.time() + 60
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
                self.fail(f"Juice Shop not reachable: {last_err}")

            orch = AuditOrchestrator()
            out = Path("/tmp/juiceshop_audit.json")
            report = orch.run(target, out, mode="normal", nuclei_rate_limit=1, gobuster_threads=5)
            self.assertTrue(out.exists())
            self.assertEqual(report.get("target"), target)
            self.assertIn("results", report)
            self.assertEqual(report.get("web_targets"), [target])
            results = report.get("results", [])
            tools = {r.get("tool"): r for r in results if isinstance(r, dict)}
            for t in ("whatweb", "nuclei", "gobuster"):
                self.assertIn(t, tools)
                self.assertFalse(tools[t].get("skipped", False))
            out.unlink(missing_ok=True)
        finally:
            subprocess.run(["docker", "compose", "-f", str(compose), "down"], check=False, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
