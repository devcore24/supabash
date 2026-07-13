import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from supabash.secure_io import atomic_write_text


class TestSecureIO(unittest.TestCase):
    def test_atomic_write_replaces_content_with_owner_only_permissions(self):
        with TemporaryDirectory(dir="/tmp") as td:
            path = Path(td) / "secret.txt"
            path.write_text("old", encoding="utf-8")
            path.chmod(0o644)

            atomic_write_text(path, "new")

            self.assertEqual(path.read_text(encoding="utf-8"), "new")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(list(path.parent.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
