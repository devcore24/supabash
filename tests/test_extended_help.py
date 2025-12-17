import os
import subprocess
import sys
import unittest
from pathlib import Path


class TestExtendedHelp(unittest.TestCase):
    def test_top_level_help_includes_command_parameters(self):
        repo_root = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo_root / "src") + os.pathsep + env.get("PYTHONPATH", "")

        proc = subprocess.run(
            [sys.executable, "-m", "supabash", "--help"],
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = proc.stdout
        self.assertIn("Command Parameters", out)
        # sanity: a couple of known options should be mentioned in the extended view
        self.assertIn("--profile", out)
        self.assertIn("--nuclei-rate", out)


if __name__ == "__main__":
    unittest.main()

