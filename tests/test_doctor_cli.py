import unittest
from unittest.mock import patch

from typer.testing import CliRunner
import supabash.__main__ as main_module


runner = CliRunner()


class TestDoctorCLI(unittest.TestCase):
    def test_doctor_ok_when_required_bins_present(self):
        def fake_which(name: str):
            required = {"nmap", "whatweb", "nuclei", "gobuster"}
            if name in required:
                return f"/usr/bin/{name}"
            return None

        with patch("supabash.__main__.shutil.which", side_effect=fake_which), patch(
            "supabash.__main__.importlib.import_module", return_value=object()
        ):
            result = runner.invoke(main_module.app, ["doctor"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Doctor: OK", result.stdout)

    def test_doctor_fails_when_required_bin_missing(self):
        def fake_which(name: str):
            if name == "nmap":
                return None
            return f"/usr/bin/{name}"

        with patch("supabash.__main__.shutil.which", side_effect=fake_which), patch(
            "supabash.__main__.importlib.import_module", return_value=object()
        ):
            result = runner.invoke(main_module.app, ["doctor"])
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("bin:nmap", result.stdout)


if __name__ == "__main__":
    unittest.main()

