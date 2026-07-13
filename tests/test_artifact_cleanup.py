import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_artifacts import cleanup_artifact


class TestArtifactCleanup(unittest.TestCase):
    def test_cleanup_removes_report_sidecars_and_evidence_bundle(self):
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"SUPABASH_TEST_REPORT_DIR": td, "SUPABASH_KEEP_TEST_REPORTS": "0"},
        ):
            root = Path(td)
            report = root / "run.json"
            lint_json = root / "run-lint.json"
            lint_md = root / "run-lint.md"
            evidence = root / "evidence" / "run"
            evidence.mkdir(parents=True)
            for path in (report, lint_json, lint_md, evidence / "manifest.json"):
                path.write_text("{}", encoding="utf-8")
            cleanup_artifact(report)
            self.assertFalse(report.exists())
            self.assertFalse(lint_json.exists())
            self.assertFalse(lint_md.exists())
            self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
