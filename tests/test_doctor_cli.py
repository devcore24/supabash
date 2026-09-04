import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner
import supabash.__main__ as main_module
import supabash.codex_runtime as codex_runtime_module
from supabash.codex_runtime import CodexPreflight, CodexRuntime


runner = CliRunner()


class TestDoctorCLI(unittest.TestCase):
    def test_inline_config_secret_detection_ignores_placeholders_and_env_refs(self):
        config = {
            "one": {"api_key": "YOUR_KEY_HERE"},
            "two": {"api_key": "${OPENAI_API_KEY}"},
            "three": {"api_key": "literal-secret"},
            "four": {"api_key_env": "BROWSER_USE_API_KEY"},
        }

        self.assertEqual(
            main_module._inline_config_secret_paths(config),
            ["$.three.api_key"],
        )

    def test_inline_config_secret_detection_is_recursive_and_format_aware(self):
        openai_canary = "sk-proj-" + ("A" * 48)
        pem_begin = "-----BEGIN " + "PRIVATE KEY-----"
        pem_end = "-----END " + "PRIVATE KEY-----"
        private_key_canary = (
            f"{pem_begin}\n"
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
            f"{pem_end}"
        )
        config = {
            "integrations": [
                {"api-key": "literal-api-key"},
                {
                    "headers": [
                        {"authorization": "Bearer literal-bearer-token"},
                    ]
                },
                {"auth": {"cookies": [{"value": "literal-cookie"}]}},
                {"token": "literal-generic-token"},
            ],
            "unknown_provider_value": openai_canary,
            "unknown_private_material": private_key_canary,
            "safe": [
                {"client-secret": "${CLIENT_SECRET}"},
                {"cookie": "env:SESSION_COOKIE"},
                {"token": "<redacted>"},
                {"api_key": "YOUR_OPENAI_API_KEY"},
            ],
        }

        self.assertEqual(
            main_module._inline_config_secret_paths(config),
            [
                "$.integrations[0].api-key",
                "$.integrations[1].headers[0].authorization",
                "$.integrations[2].auth.cookies",
                "$.integrations[3].token",
                "$.unknown_provider_value",
                "$.unknown_private_material",
            ],
        )

    def test_doctor_ok_when_required_bins_present(self):
        def fake_which(name: str):
            required = {"nmap", "whatweb", "nuclei", "gobuster"}
            if name in required:
                return f"/usr/bin/{name}"
            return None

        with patch("supabash.__main__.shutil.which", side_effect=fake_which), patch(
            "supabash.__main__.import_module", return_value=object()
        ):
            result = runner.invoke(main_module.app, ["doctor"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Doctor: OK", result.stdout)
        self.assertIn("Tool checks were presence-only", result.stdout)

    def test_doctor_codex_marks_tool_checks_as_presence_only_without_deep(self):
        inspection = CodexPreflight(
            command="/usr/bin/codex",
            installed=True,
            version="codex-cli 0.146.1",
            authenticated=True,
            auth_mode="chatgpt",
            is_chatgpt=True,
            ready=True,
            error=None,
        )
        with patch(
            "supabash.__main__.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch.object(
            CodexRuntime, "inspect", return_value=inspection
        ), patch.object(
            codex_runtime_module, "ambient_codex_context_keys", return_value=()
        ):
            result = runner.invoke(main_module.app, ["doctor", "--codex", "--json"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["check_mode"], "presence_only")
        self.assertFalse(payload["deep_check_run"])
        tool_checks = [
            item for item in payload["checks"] if item["details"].get("tool")
        ]
        self.assertTrue(tool_checks)
        for check in tool_checks:
            self.assertIn("presence-only check; deep check not run", check["message"])
            self.assertEqual(check["details"]["check_mode"], "presence_only")
            self.assertFalse(check["details"]["deep_check_run"])
            self.assertNotIn("health_return_code", check["details"])
            self.assertNotIn("detected_version", check["details"])
            self.assertNotIn("version_status", check["details"])

    def test_doctor_detects_direct_venv_python_without_environment_variable(self):
        def fake_which(name: str):
            return f"/usr/bin/{name}"

        with patch.dict(os.environ, {}, clear=False), patch(
            "supabash.__main__.shutil.which", side_effect=fake_which
        ), patch("supabash.__main__.import_module", return_value=object()), patch.object(
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
            "supabash.__main__.import_module", return_value=object()
        ):
            result = runner.invoke(main_module.app, ["doctor"])
        self.assertNotEqual(result.exit_code, 0, result.stdout)
        self.assertIn("bin:nmap", result.stdout)

    def test_doctor_deep_runs_only_registry_health_probes(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="tool version 99.0.0\n", stderr="")

        with patch(
            "supabash.__main__.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"
        ), patch("supabash.__main__.subprocess.run", side_effect=fake_run), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch(
            "supabash.tool_registry.python_distribution_version", return_value="99.0.0"
        ):
            result = runner.invoke(main_module.app, ["doctor", "--deep", "--json"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        nmap = next(item for item in payload["checks"] if item["name"] == "bin:nmap")
        self.assertTrue(nmap["ok"])
        self.assertEqual(nmap["details"]["health_return_code"], 0)
        self.assertTrue(calls)
        for command, kwargs in calls:
            self.assertIsInstance(command, list)
            self.assertTrue(command[0].startswith("/usr/bin/"))
            self.assertLessEqual(int(kwargs["timeout"]), 30)
            self.assertFalse(kwargs["check"])

    def test_doctor_deep_prefers_system_httpx_over_shadowing_venv_cli(self):
        calls = []

        def fake_which(candidate):
            if candidate == "/usr/local/bin/httpx":
                return candidate
            if candidate == "/usr/bin/httpx":
                return None
            if candidate == "httpx":
                return "/project/venv/bin/httpx"
            if str(candidate).startswith("/"):
                return None
            return f"/usr/bin/{candidate}"

        def fake_run(command, **_kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="tool version 99.0.0\n", stderr="")

        with patch(
            "supabash.__main__.shutil.which", side_effect=fake_which
        ), patch(
            "supabash.__main__.subprocess.run", side_effect=fake_run
        ), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch(
            "supabash.tool_registry.python_distribution_version", return_value="99.0.0"
        ):
            result = runner.invoke(main_module.app, ["doctor", "--deep", "--json"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        httpx = next(item for item in payload["checks"] if item["name"] == "bin:httpx")
        self.assertEqual(httpx["details"]["which"], "/usr/local/bin/httpx")
        self.assertEqual(
            httpx["details"]["candidates"]["httpx"],
            "/project/venv/bin/httpx",
        )
        self.assertIn(
            ["/usr/local/bin/httpx", "-version"],
            calls,
        )

    def test_doctor_deep_selects_compatible_httpx_over_older_first_candidate(self):
        def fake_which(candidate):
            if candidate == "/usr/local/bin/httpx":
                return "/opt/old/httpx"
            if candidate == "/usr/bin/httpx":
                return None
            if candidate == "httpx":
                return "/opt/current/httpx"
            if str(candidate).startswith("/"):
                return None
            return f"/usr/bin/{candidate}"

        def fake_run(command, **_kwargs):
            if command[0] == "/opt/old/httpx":
                output = "httpx version v1.8.1\n"
            elif command[0] == "/opt/current/httpx":
                output = "httpx version v1.10.0\n"
            else:
                output = "tool version 99.0.0\n"
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        with patch(
            "supabash.__main__.shutil.which", side_effect=fake_which
        ), patch(
            "supabash.__main__.subprocess.run", side_effect=fake_run
        ), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch(
            "supabash.tool_registry.python_distribution_version", return_value="99.0.0"
        ):
            result = runner.invoke(main_module.app, ["doctor", "--deep", "--json"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        httpx = next(item for item in payload["checks"] if item["name"] == "bin:httpx")
        self.assertEqual(httpx["details"]["which"], "/opt/current/httpx")
        checks = {item["path"]: item for item in httpx["details"]["candidate_checks"]}
        self.assertEqual(checks["/opt/old/httpx"]["version_status"], "outdated")
        self.assertEqual(checks["/opt/current/httpx"]["version_status"], "recommended")
        self.assertTrue(checks["/opt/current/httpx"]["selected"])

    def test_doctor_deep_detects_outdated_and_broken_tools(self):
        def fake_run(command, **_kwargs):
            executable = str(command[0])
            if executable.endswith("nuclei"):
                return SimpleNamespace(
                    returncode=0,
                    stdout="Current nuclei version: v2.9.8\n",
                    stderr="",
                )
            if executable.lower().endswith("theharvester"):
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Traceback (most recent call last):\nModuleNotFoundError: netaddr\n",
                )
            return SimpleNamespace(returncode=0, stdout="tool version 99.0.0\n", stderr="")

        with patch(
            "supabash.__main__.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch("supabash.__main__.subprocess.run", side_effect=fake_run), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch(
            "supabash.tool_registry.python_distribution_version", return_value="99.0.0"
        ):
            result = runner.invoke(main_module.app, ["doctor", "--deep", "--json"])

        self.assertNotEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        nuclei = next(item for item in payload["checks"] if item["name"] == "bin:nuclei")
        harvester = next(item for item in payload["checks"] if item["name"] == "bin:theHarvester")
        self.assertFalse(nuclei["ok"])
        self.assertEqual(nuclei["details"]["version_status"], "outdated")
        self.assertEqual(nuclei["details"]["detected_version"], "v2.9.8")
        self.assertFalse(harvester["ok"])
        self.assertEqual(harvester["details"]["health_fatal_marker"], "traceback (most recent call last)")

    def test_doctor_deep_fails_closed_when_version_cannot_be_established(self):
        def fake_run(_command, **_kwargs):
            return SimpleNamespace(returncode=0, stdout="healthy\n", stderr="")

        with patch(
            "supabash.__main__.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch("supabash.__main__.subprocess.run", side_effect=fake_run), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch(
            "supabash.tool_registry.python_distribution_version", return_value=None
        ):
            result = runner.invoke(main_module.app, ["doctor", "--deep", "--json"])

        self.assertNotEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        nuclei = next(item for item in payload["checks"] if item["name"] == "bin:nuclei")
        self.assertFalse(nuclei["ok"])
        self.assertEqual(nuclei["details"]["version_status"], "unavailable")
        self.assertIn("version metadata was unavailable", nuclei["message"])

    def test_doctor_deep_detects_outdated_browser_use_distribution(self):
        def fake_run(_command, **_kwargs):
            return SimpleNamespace(returncode=0, stdout="tool version 99.0.0\n", stderr="")

        with patch(
            "supabash.__main__.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch("supabash.__main__.subprocess.run", side_effect=fake_run), patch(
            "supabash.__main__.import_module", return_value=object()
        ), patch(
            "supabash.tool_registry.python_distribution_version", return_value="0.12.1"
        ):
            result = runner.invoke(main_module.app, ["doctor", "--deep", "--json"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        payload = json.loads(result.stdout)
        browser = next(item for item in payload["checks"] if item["name"] == "bin:browser-use")
        self.assertFalse(browser["ok"])
        self.assertEqual(browser["details"]["detected_version"], "0.12.1")
        self.assertEqual(browser["details"]["version_status"], "outdated")
        self.assertIn("older than recommended 0.13.7", browser["message"])

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
            "supabash.__main__.import_module", return_value=object()
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
            "supabash.__main__.import_module", return_value=object()
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
            "supabash.__main__.import_module", return_value=object()
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
            "supabash.__main__.import_module", return_value=object()
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
