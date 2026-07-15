import json
import os
import unittest
from unittest.mock import patch

from typer.testing import CliRunner
import supabash.__main__ as main_module
import supabash.codex_runtime as codex_runtime_module
from supabash.codex_runtime import CodexPreflight, CodexRuntime


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

    def test_doctor_detects_direct_venv_python_without_environment_variable(self):
        def fake_which(name: str):
            return f"/usr/bin/{name}"

        with patch.dict(os.environ, {}, clear=False), patch(
            "supabash.__main__.shutil.which", side_effect=fake_which
        ), patch("supabash.__main__.importlib.import_module", return_value=object()), patch.object(
            main_module.sys, "prefix", "/tmp/project/venv"
        ), patch.object(main_module.sys, "base_prefix", "/usr"):
            os.environ.pop("VIRTUAL_ENV", None)
            result = runner.invoke(main_module.app, ["doctor", "--json"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        venv = next(item for item in payload["checks"] if item["name"] == "venv")
        self.assertTrue(venv["ok"])
        self.assertEqual(venv["message"], "/tmp/project/venv")
        self.assertEqual(venv["details"]["base_prefix"], "/usr")


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

    def test_doctor_codex_requires_chatgpt_authentication(self):
        inspection = CodexPreflight(
            command="/usr/bin/codex",
            installed=True,
            version="codex-cli 0.144.3",
            authenticated=True,
            auth_mode="chatgpt",
            is_chatgpt=True,
            ready=True,
            error=None,
        )
        with patch("supabash.__main__.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch(
            "supabash.__main__.importlib.import_module", return_value=object()
        ), patch.object(CodexRuntime, "inspect", return_value=inspection), patch.object(
            codex_runtime_module, "ambient_codex_context_keys", return_value=()
        ):
            result = runner.invoke(main_module.app, ["doctor", "--codex", "--json"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        auth = next(item for item in payload["checks"] if item["name"] == "codex.auth")
        self.assertTrue(auth["ok"])
        self.assertTrue(auth["required"])
        self.assertEqual(auth["message"], "chatgpt")

    def test_doctor_codex_rejects_api_key_login(self):
        inspection = CodexPreflight(
            command="/usr/bin/codex",
            installed=True,
            version="codex-cli 0.144.3",
            authenticated=True,
            auth_mode="api_key",
            is_chatgpt=False,
            ready=False,
            error="Codex must be logged in using a ChatGPT subscription.",
        )
        with patch("supabash.__main__.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch(
            "supabash.__main__.importlib.import_module", return_value=object()
        ), patch.object(CodexRuntime, "inspect", return_value=inspection), patch.object(
            codex_runtime_module, "ambient_codex_context_keys", return_value=()
        ):
            result = runner.invoke(main_module.app, ["doctor", "--codex", "--json"])

        self.assertNotEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        auth = next(item for item in payload["checks"] if item["name"] == "codex.auth")
        self.assertFalse(auth["ok"])
        self.assertEqual(auth["message"], "api_key")

    def test_doctor_codex_rejects_nested_codex_task_context(self):
        inspection = CodexPreflight(
            command="/usr/bin/codex",
            installed=True,
            version="codex-cli 0.144.3",
            authenticated=True,
            auth_mode="chatgpt",
            is_chatgpt=True,
            ready=True,
            error=None,
        )
        with patch("supabash.__main__.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch(
            "supabash.__main__.importlib.import_module", return_value=object()
        ), patch.object(CodexRuntime, "inspect", return_value=inspection), patch.object(
            codex_runtime_module,
            "ambient_codex_context_keys",
            return_value=("CODEX_THREAD_ID",),
        ):
            result = runner.invoke(main_module.app, ["doctor", "--codex", "--json"])

        self.assertNotEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        context = next(item for item in payload["checks"] if item["name"] == "codex.context")
        self.assertFalse(context["ok"])
        self.assertNotIn("CODEX_THREAD_ID=", context["message"])

    def test_doctor_codex_rejects_global_agents_instructions(self):
        inspection = CodexPreflight(
            command="/usr/bin/codex",
            installed=True,
            version="codex-cli 0.144.3",
            authenticated=True,
            auth_mode="chatgpt",
            is_chatgpt=True,
            ready=False,
            error="Global AGENTS instructions are not allowed",
            global_instructions_ok=False,
            global_instruction_files=("/home/example/.codex/AGENTS.md",),
        )
        with patch("supabash.__main__.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch(
            "supabash.__main__.importlib.import_module", return_value=object()
        ), patch.object(CodexRuntime, "inspect", return_value=inspection), patch.object(
            codex_runtime_module, "ambient_codex_context_keys", return_value=()
        ):
            result = runner.invoke(main_module.app, ["doctor", "--codex", "--json"])

        self.assertNotEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        instructions = next(
            item for item in payload["checks"] if item["name"] == "codex.instructions"
        )
        self.assertFalse(instructions["ok"])
        self.assertEqual(
            instructions["details"]["files"],
            ["/home/example/.codex/AGENTS.md"],
        )


if __name__ == "__main__":
    unittest.main()
