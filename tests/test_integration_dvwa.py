import os
import shutil
import subprocess
import time
import unittest
import warnings
from pathlib import Path
from urllib.request import urlopen

from supabash.audit import AuditOrchestrator
from tests.test_artifacts import artifact_path, cleanup_artifact


def _has_bin(name: str) -> bool:
    return shutil.which(name) is not None


def _nuclei_rate_limit() -> int:
    raw = os.getenv("SUPABASH_NUCLEI_RATE", "100000")
    try:
        rate = int(raw)
    except Exception:
        rate = 20
    return max(1, rate)


def _nuclei_tags() -> str | None:
    value = os.getenv("SUPABASH_NUCLEI_TAGS", "exposure,misconfig,default-login")
    value = value.strip()
    return value or None


def _nuclei_severity() -> str | None:
    value = os.getenv("SUPABASH_NUCLEI_SEVERITY", "critical,high")
    value = value.strip()
    return value or None


def _nuclei_templates() -> str | None:
    raw = os.getenv("SUPABASH_NUCLEI_TEMPLATES", "").strip()
    if raw:
        return raw
    template = (
        Path(__file__).resolve().parents[1]
        / "tests"
        / "fixtures"
        / "nuclei"
        / "dvwa-min.yaml"
    )
    return str(template) if template.exists() else None


class TestIntegrationDVWA(unittest.TestCase):
    @unittest.skipUnless(os.getenv("SUPABASH_INTEGRATION") == "1", "set SUPABASH_INTEGRATION=1 to run")
    def test_audit_against_dvwa(self):
        orig_showwarning = warnings.showwarning

        def _filtered_showwarning(message, category, filename, lineno, file=None, line=None):
            if "Pydantic serializer warnings" in str(message):
                return
            return orig_showwarning(message, category, filename, lineno, file=file, line=line)

        warnings.showwarning = _filtered_showwarning
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
            report = orch.run(
                target,
                out,
                mode="normal",
                nuclei_rate_limit=_nuclei_rate_limit(),
                gobuster_threads=5,
                nuclei_templates=_nuclei_templates(),
                nuclei_tags=_nuclei_tags(),
                nuclei_severity=_nuclei_severity(),
            )
            self.assertTrue(out.exists())
            self.assertEqual(report.get("target"), target)
            self.assertIn("results", report)
            web_targets = report.get("web_targets") or []
            self.assertIn(target, web_targets)
            cleanup_artifact(out)
        finally:
            warnings.showwarning = orig_showwarning
            subprocess.run(["docker", "compose", "-f", compose, "down"], check=False, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
