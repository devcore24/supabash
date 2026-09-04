import copy
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
from typer.testing import CliRunner

import supabash.__main__ as main_module

from supabash.config import DEFAULT_CONFIG, ConfigManager, resolve_config_file
from supabash.session_state import default_chat_state_path


class TestConfigPaths(unittest.TestCase):
    def test_example_matches_default_config_and_contains_no_secrets(self):
        example_path = Path(__file__).resolve().parents[1] / "config.yaml.example"
        example = yaml.safe_load(example_path.read_text(encoding="utf-8"))

        self.assertEqual(example, DEFAULT_CONFIG)
        self.assertEqual(main_module._inline_config_secret_paths(example), [])

    def test_explicit_config_override_wins(self):
        with tempfile.TemporaryDirectory() as td:
            expected = Path(td) / "custom.yaml"
            resolved = resolve_config_file(
                cwd=Path(td) / "cwd",
                home=Path(td) / "home",
                source_root=Path(td) / "installed-package",
                environ={"SUPABASH_CONFIG": str(expected)},
            )
            self.assertEqual(resolved, expected.resolve())

    def test_existing_cwd_config_is_preferred(self):
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td) / "project"
            cwd.mkdir()
            expected = cwd / "config.yaml"
            expected.write_text("core: {}\n", encoding="utf-8")
            resolved = resolve_config_file(
                cwd=cwd,
                home=Path(td) / "home",
                source_root=Path(td) / "installed-package",
                environ={},
            )
            self.assertEqual(resolved, expected.resolve())

    def test_installed_layout_uses_xdg_user_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            resolved = resolve_config_file(
                cwd=root / "cwd",
                home=root / "home",
                source_root=root / "site-packages",
                environ={"XDG_CONFIG_HOME": str(root / "xdg")},
            )
            self.assertEqual(resolved, (root / "xdg" / "supabash" / "config.yaml").resolve())
            self.assertNotIn("site-packages", str(resolved))

    def test_source_checkout_keeps_repo_local_config(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            source.mkdir()
            (source / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
            resolved = resolve_config_file(
                cwd=Path(td) / "other",
                home=Path(td) / "home",
                source_root=source,
                environ={},
            )
            self.assertEqual(resolved, (source / "config.yaml").resolve())

    def test_explicit_config_works_with_unusable_legacy_home(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            root = Path(td)
            unusable_home = root / "home-is-a-file"
            unusable_home.write_text("not a directory", encoding="utf-8")
            explicit = root / "config" / "config.yaml"
            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(unusable_home),
                    "SUPABASH_CONFIG": str(explicit),
                    "EXPECTED_CONFIG": str(explicit.resolve()),
                }
            )
            script = (
                "import os\n"
                "from pathlib import Path\n"
                "from supabash.config import config_manager\n"
                "assert config_manager.config_file == Path(os.environ[\"EXPECTED_CONFIG\"])\n"
            )

            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertTrue(explicit.is_file())
            self.assertTrue(unusable_home.is_file())
            self.assertEqual(stat.S_IMODE(explicit.stat().st_mode), 0o600)

    def test_loading_existing_config_hardens_permissions_without_creating_fallback(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            root = Path(td)
            config_file = root / "config.yaml"
            config_file.write_text("core: {}\nllm: {}\nchat: {}\ntools: {}\n", encoding="utf-8")
            config_file.chmod(0o644)
            fallback_file = root / "legacy" / ".supabash" / "config.yaml"
            manager = ConfigManager.__new__(ConfigManager)
            manager.config_file = config_file
            manager.fallback_file = fallback_file

            loaded = manager.load_config()

            self.assertIsInstance(loaded, dict)
            self.assertEqual(stat.S_IMODE(config_file.stat().st_mode), 0o600)
            self.assertFalse(fallback_file.parent.exists())

    def test_codex_defaults_are_added_without_overwriting_user_values(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            root = Path(td)
            config_file = root / "config.yaml"
            config_file.write_text(
                "codex:\n"
                "  command: /opt/codex/bin/codex\n"
                "  timeout_seconds: 45\n"
                "  ignore_user_config: false\n"
                "  custom_setting: retained\n",
                encoding="utf-8",
            )
            manager = ConfigManager.__new__(ConfigManager)
            manager.config_file = config_file
            manager.fallback_file = root / "legacy" / "config.yaml"

            loaded = manager.load_config()

            self.assertEqual(loaded["codex"]["command"], "/opt/codex/bin/codex")
            self.assertIsNone(loaded["codex"]["codex_home"])
            self.assertEqual(loaded["codex"]["timeout_seconds"], 45)
            self.assertFalse(loaded["codex"]["ignore_user_config"])
            self.assertEqual(loaded["codex"]["custom_setting"], "retained")
            self.assertEqual(loaded["codex"]["sandbox"], "read-only")
            self.assertTrue(loaded["codex"]["require_chatgpt"])
            self.assertFalse(loaded["codex"]["persistent_thread"])
            self.assertEqual(loaded["codex"]["preflight_timeout_seconds"], 10)
            self.assertEqual(loaded["codex"]["max_input_chars"], 24000)
            self.assertEqual(loaded["codex"]["max_events"], 500)
            self.assertEqual(loaded["codex"]["max_event_chars"], 16384)
            self.assertIn("shell_tool", loaded["codex"]["disabled_features"])

    def test_missing_codex_block_uses_an_independent_default_copy(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            root = Path(td)
            config_file = root / "config.yaml"
            config_file.write_text("core: {}\n", encoding="utf-8")
            manager = ConfigManager.__new__(ConfigManager)
            manager.config_file = config_file
            manager.fallback_file = root / "legacy" / "config.yaml"

            loaded = manager.load_config()

            self.assertEqual(loaded["codex"], DEFAULT_CONFIG["codex"])
            self.assertIsNot(loaded["codex"], DEFAULT_CONFIG["codex"])
            loaded["codex"]["command"] = "changed"
            loaded["codex"]["disabled_features"].append("test-only")
            self.assertEqual(DEFAULT_CONFIG["codex"]["command"], "codex")
            self.assertNotIn("test-only", DEFAULT_CONFIG["codex"]["disabled_features"])

    def test_failed_atomic_save_preserves_existing_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            config_file = root / "config.yaml"
            original = "value: old\n"
            config_file.write_text(original, encoding="utf-8")
            config_file.chmod(0o600)
            manager = ConfigManager.__new__(ConfigManager)
            manager.config_file = config_file
            manager.fallback_file = root / "legacy" / "config.yaml"
            manager.config = {"value": "old"}

            with patch("supabash.config.os.replace", side_effect=OSError("simulated replace failure")):
                saved = manager.save_config({"value": "new"})

            self.assertFalse(saved)
            self.assertEqual(config_file.read_text(encoding="utf-8"), original)
            self.assertFalse(list(root.glob(".config.yaml.*.tmp")))

    def test_setters_are_copy_on_write_and_propagate_save_failure(self):
        base = {
            "core": {
                "allowed_hosts": ["localhost"],
                "consent_accepted": False,
                "allow_public_ips": False,
            },
            "llm": {
                "provider": "openai",
                "openai": {
                    "api_key": "old-key",
                    "model": "old-model",
                    "api_base": "https://old.example",
                },
            },
        }
        manager = ConfigManager.__new__(ConfigManager)
        operations = [
            ("key", lambda: manager.set_llm_key("openai", "new-key")),
            ("provider", lambda: manager.set_active_provider("anthropic")),
            ("model", lambda: manager.set_model("openai", "new-model")),
            ("api_base", lambda: manager.set_api_base("openai", "")),
            ("add_host", lambda: manager.add_allowed_host("example.test")),
            ("remove_host", lambda: manager.remove_allowed_host("localhost")),
            ("consent", lambda: manager.set_consent_accepted(True)),
            ("public_ips", lambda: manager.set_allow_public_ips(True)),
        ]

        for name, operation in operations:
            with self.subTest(name=name):
                manager.config = copy.deepcopy(base)
                with patch.object(manager, "save_config", return_value=False) as save:
                    saved = operation()

                self.assertFalse(saved)
                self.assertEqual(manager.config, base)
                candidate = save.call_args.args[0]
                self.assertIsNot(candidate, manager.config)
                self.assertNotEqual(candidate, base)

    def test_model_update_preserves_existing_inline_key(self):
        manager = ConfigManager.__new__(ConfigManager)
        manager.config = {
            "llm": {
                "provider": "openai",
                "openai": {
                    "api_key": "existing-secret",
                    "model": "old-model",
                },
            },
        }

        with patch.object(manager, "save_config", return_value=True) as save:
            saved = manager.configure_llm_provider("openai", model="new-model")

        self.assertTrue(saved)
        candidate = save.call_args.args[0]
        self.assertEqual(candidate["llm"]["openai"]["api_key"], "existing-secret")
        self.assertEqual(candidate["llm"]["openai"]["model"], "new-model")
        self.assertEqual(manager.config["llm"]["openai"]["model"], "old-model")

    def test_mistral_is_treated_as_a_standard_cli_provider(self):
        manager = Mock()
        manager.config_file = Path("/tmp/config.yaml")
        manager.get_llm_config.return_value = {
            "provider": "openai",
            "config": {"api_key": "existing-secret", "model": "old-model"},
        }
        manager.configure_llm_provider.return_value = True

        with patch.object(main_module, "config_manager", manager):
            result = CliRunner().invoke(
                main_module.app,
                ["config", "--provider", "mistral", "--model", "mistral-test"],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("not a standard provider", result.output)
        manager.configure_llm_provider.assert_called_once_with(
            "mistral",
            make_active=True,
            model="mistral-test",
        )

    def test_noninteractive_config_failure_exits_without_success_claim(self):
        manager = Mock()
        manager.config_file = Path("/tmp/config.yaml")
        manager.add_allowed_host.return_value = False

        with patch.object(main_module, "config_manager", manager):
            result = CliRunner().invoke(
                main_module.app,
                ["config", "--allow-host", "example.test"],
            )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Configuration update failed", result.output)
        self.assertNotIn("Added allowed host", result.output)
        self.assertNotIn("Configuration saved", result.output)

    def test_interactive_config_failure_exits_without_success_claim(self):
        manager = Mock()
        manager.config_file = Path("/tmp/config.yaml")
        manager.config = {
            "llm": {
                "provider": "openai",
                "openai": {"api_key": "", "model": "gpt-test"},
            }
        }
        manager.get_allow_public_ips.return_value = False
        manager.set_active_provider.return_value = False

        with patch.object(main_module, "config_manager", manager):
            result = CliRunner().invoke(
                main_module.app,
                ["config"],
                input="1\nopenai\n",
            )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Configuration update failed", result.output)
        self.assertNotIn("Active provider is now", result.output)
        self.assertNotIn("Settings updated", result.output)

    def test_chat_state_defaults_to_current_working_directory(self):
        with tempfile.TemporaryDirectory() as td:
            previous = Path.cwd()
            try:
                import os

                os.chdir(td)
                self.assertEqual(
                    default_chat_state_path(),
                    (Path(td) / ".supabash" / "chat_state.json").resolve(),
                )
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
