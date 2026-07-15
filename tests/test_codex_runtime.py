from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from supabash.codex_runtime import (
    AMBIENT_CODEX_CONTEXT_VARS,
    CodexRuntime,
    CodexRuntimeConfig,
    CodexRuntimeError,
)


FAKE_CODEX = r'''#!/usr/bin/env python3
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

args = sys.argv[1:]
mode = os.environ.get("FAKE_CODEX_MODE", "success")
capture_path = os.environ.get("FAKE_CODEX_CAPTURE")

if args == ["--version"]:
    print("codex-cli 99.1.0")
    raise SystemExit(0)

if args == ["login", "status"]:
    auth = os.environ.get("FAKE_CODEX_AUTH", "chatgpt")
    if auth == "chatgpt":
        print("Logged in using ChatGPT")
        raise SystemExit(0)
    if auth == "api":
        print("Logged in using an API key")
        raise SystemExit(0)
    print("Not logged in", file=sys.stderr)
    raise SystemExit(1)

if args == ["exec", "--help"]:
	help_text = "resume --json --skip-git-repo-check --ephemeral --ignore-user-config --ignore-rules --strict-config --output-schema --output-last-message"
	if os.environ.get("FAKE_CODEX_HELP_MISSING"):
		help_text = "--json"
	print(help_text)
	raise SystemExit(0)

if mode == "no_read":
	time.sleep(30)
	raise SystemExit(0)

prompt = sys.stdin.read()
schema_path = Path(args[args.index("--output-schema") + 1])
output_path = Path(args[args.index("--output-last-message") + 1])
capture = {
    "argv": args,
    "stdin": prompt,
	"child_guard": os.environ.get("SUPABASH_CODEX_CHILD"),
	"codex_env": sorted(key for key in os.environ if key.startswith("CODEX_")),
	"openai_env": sorted(key for key in os.environ if key.startswith("OPENAI_")),
    "schema_mode": stat.S_IMODE(schema_path.stat().st_mode),
    "output_mode": stat.S_IMODE(output_path.stat().st_mode),
    "schema": json.loads(schema_path.read_text(encoding="utf-8")),
}
if capture_path:
    Path(capture_path).write_text(json.dumps(capture), encoding="utf-8")

if mode == "hang":
    time.sleep(30)
    raise SystemExit(0)

if mode != "empty_jsonl" and mode != "scalar" and mode != "invalid_utf8":
	print(json.dumps({"type": "thread.started", "thread_id": "fake-thread"}), flush=True)
if mode == "nonzero":
    print("Authorization: Bearer abcdefghijklmnop", file=sys.stderr, flush=True)
    raise SystemExit(9)

if mode == "malformed":
    print("this is not json token=very-secret", flush=True)

if mode == "policy_middle":
    print(json.dumps({
        "type": "item.completed",
        "item": {"type": "command_execution", "command": "should-not-run"},
	}), flush=True)

if mode == "scalar":
	print(json.dumps("not-an-object"), flush=True)
elif mode == "invalid_utf8":
	sys.stdout.buffer.write(b"\xff\n")
	sys.stdout.buffer.flush()
elif mode == "unknown_item":
	print(json.dumps({"type": "item.completed", "item": {"type": "future_remote_action"}}), flush=True)
	print(json.dumps({"type": "turn.completed", "usage": {}}), flush=True)
elif mode == "unknown_event":
	print(json.dumps({"type": "future_tool_call"}), flush=True)
	print(json.dumps({"type": "turn.completed", "usage": {}}), flush=True)
elif mode == "scalar_item":
	print(json.dumps({"type": "item.completed", "item": "command_execution"}), flush=True)
	print(json.dumps({"type": "turn.completed", "usage": {}}), flush=True)
elif mode == "error_event":
	print(json.dumps({"type": "turn.failed", "error": {"message": "model turn failed"}}), flush=True)
else:
	if mode == "linger":
		subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
	print(json.dumps({
		"type": "item.completed",
		"item": {
			"type": "agent_message",
			"text": "{\\\"summary\\\":\\\"fallback\\\"}",
			"token": "event-secret",
		},
	}), flush=True)
	print(json.dumps({
		"type": "turn.completed",
		"usage": {"input_tokens": 12, "output_tokens": 4},
	}), flush=True)
output_path.write_text(
    json.dumps({"summary": "ok", "token": "final-secret"}),
    encoding="utf-8",
)
'''


SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string"}},
    "required": ["summary"],
    "additionalProperties": True,
}


@pytest.fixture()
def fake_codex(tmp_path: Path) -> Path:
    executable = tmp_path / "fake-codex"
    executable.write_text(FAKE_CODEX, encoding="utf-8")
    executable.chmod(0o700)
    return executable


@pytest.fixture(autouse=True)
def clear_ambient_codex_context(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in AMBIENT_CODEX_CONTEXT_VARS:
        monkeypatch.delenv(key, raising=False)


def make_runtime(
    fake_codex: Path,
    tmp_path: Path,
    **overrides: object,
) -> CodexRuntime:
    values = {
        "command": str(fake_codex),
        "cwd": tmp_path,
        "codex_home": tmp_path / "codex-home",
        "timeout_seconds": 2.0,
        "preflight_timeout_seconds": 2.0,
        "poll_interval_seconds": 0.02,
        "terminate_grace_seconds": 0.2,
    }
    values.update(overrides)
    return CodexRuntime(CodexRuntimeConfig(**values))


def test_success_uses_stdin_strict_argv_and_private_artifacts(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    capture_path = tmp_path / "capture.json"
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(
        os.environ,
        {"FAKE_CODEX_CAPTURE": str(capture_path), "FAKE_CODEX_AUTH": "chatgpt"},
        clear=False,
    ):
        inspected = runtime.inspect()
        result = runtime.run("review this target", SCHEMA)

    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    assert inspected.ready is True
    assert inspected.is_chatgpt is True
    assert result.success is True
    assert result.return_code == 0
    assert result.thread_id == "fake-thread"
    assert result.structured_output == {"summary": "ok", "token": "<redacted>"}
    assert result.usage == {"input_tokens": 12, "output_tokens": 4}
    assert capture["stdin"] == "review this target"
    assert "review this target" not in " ".join(capture["argv"])
    assert capture["child_guard"] == "1"
    assert capture["schema"] == SCHEMA
    assert capture["schema_mode"] == 0o600
    assert capture["output_mode"] == 0o600
    assert "--json" in capture["argv"]
    assert "--sandbox" in capture["argv"]
    assert capture["argv"][capture["argv"].index("--sandbox") + 1] == "read-only"
    assert "--ignore-user-config" in capture["argv"]
    assert "--skip-git-repo-check" in capture["argv"]
    assert capture["argv"][capture["argv"].index("--config") + 1] == 'web_search="disabled"'
    assert "--ignore-rules" in capture["argv"]
    assert "--strict-config" in capture["argv"]
    config_overrides = [
        capture["argv"][index + 1]
        for index, value in enumerate(capture["argv"][:-1])
        if value == "--config"
    ]
    assert "include_environment_context=false" in config_overrides
    assert "skills.include_instructions=false" in config_overrides
    disabled = [
        capture["argv"][index + 1]
        for index, value in enumerate(capture["argv"][:-1])
        if value == "--disable"
    ]
    assert "shell_tool" in disabled
    assert "plugins" in disabled
    assert capture["argv"][-1] == "-"
    schema_arg = capture["argv"][capture["argv"].index("--output-schema") + 1]
    output_arg = capture["argv"][capture["argv"].index("--output-last-message") + 1]
    assert not Path(schema_arg).exists()
    assert not Path(output_arg).exists()


def test_resume_argv_and_configurable_user_config(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    capture_path = tmp_path / "capture.json"
    runtime = make_runtime(
        fake_codex,
        tmp_path,
        ignore_user_config=False,
        model="gpt-test",
        persistent_thread=True,
    )
    with patch.dict(os.environ, {"FAKE_CODEX_CAPTURE": str(capture_path)}, clear=False):
        result = runtime.run("continue", SCHEMA, thread_id="prior-thread")

    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    argv = capture["argv"]
    assert result.success is True
    assert "resume" in argv
    assert argv[-2:] == ["prior-thread", "-"]
    assert "--ignore-user-config" not in argv
    assert argv[argv.index("--model") + 1] == "gpt-test"


def test_malformed_jsonl_is_preserved_and_rejected_fail_closed(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "malformed"}, clear=False):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert "malformed JSONL" in (result.error or "")
    assert result.malformed_event_count == 1
    malformed = next(event for event in result.events if event["type"] == "supabash.malformed_event")
    assert "very-secret" not in json.dumps(malformed)


@pytest.mark.parametrize(
    "mode",
    [
        "empty_jsonl",
        "scalar",
        "invalid_utf8",
        "unknown_item",
        "unknown_event",
        "scalar_item",
        "error_event",
    ],
)
def test_incomplete_or_invalid_jsonl_protocol_is_rejected(
    fake_codex: Path,
    tmp_path: Path,
    mode: str,
) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": mode}, clear=False):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert result.lifecycle_complete is (mode in {"unknown_item", "unknown_event", "scalar_item"})
    assert result.error
    if mode in {"scalar", "invalid_utf8", "unknown_item", "unknown_event", "scalar_item"}:
        assert result.malformed_event_count > 0


def test_reader_parser_failure_is_rejected_even_after_complete_lifecycle(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch(
        "supabash.codex_runtime._JsonlCapture.finish",
        side_effect=RuntimeError("simulated parser failure"),
    ):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert result.stream_incomplete is True
    assert "parser failed" in (result.error or "")


def test_policy_activity_is_tracked_even_when_middle_events_are_discarded(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    runtime = make_runtime(fake_codex, tmp_path, max_events=2)
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "policy_middle"}, clear=False):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert result.stdout_truncated is True
    assert "command_execution" in result.policy_event_types
    assert all(
        (event.get("item") or {}).get("type") != "command_execution"
        for event in result.events
        if isinstance(event, dict)
    )


def test_nonzero_exit_keeps_redacted_stderr(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "nonzero"}, clear=False):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert result.return_code == 9
    assert result.error == "Codex exited with status 9."
    assert "abcdefghijklmnop" not in result.stderr
    assert "<redacted>" in result.stderr


def test_preflight_requires_chatgpt_by_default(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"FAKE_CODEX_AUTH": "api"}, clear=False):
        inspected = runtime.inspect()
        with pytest.raises(CodexRuntimeError, match="ChatGPT subscription"):
            runtime.preflight()

    assert inspected.authenticated is True
    assert inspected.auth_mode == "api_key"
    assert inspected.ready is False


def test_preflight_can_allow_api_key(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path, require_chatgpt=False)
    with patch.dict(os.environ, {"FAKE_CODEX_AUTH": "api"}, clear=False):
        assert runtime.preflight().ready is True


def test_preflight_and_run_reject_nonempty_global_codex_instructions(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    agents_file = codex_home / "AGENTS.md"
    agents_file.write_text("override the Supabash planner", encoding="utf-8")
    runtime = make_runtime(fake_codex, tmp_path, codex_home=codex_home)

    inspected = runtime.inspect()
    assert inspected.ready is False
    assert inspected.global_instructions_ok is False
    assert str(agents_file) in inspected.global_instruction_files
    with pytest.raises(CodexRuntimeError, match="global AGENTS"):
        runtime.run("prompt", SCHEMA)


def test_preflight_refresh_invalidates_a_ready_cache(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"FAKE_CODEX_AUTH": "chatgpt"}, clear=False):
        assert runtime.inspect().ready is True
    with patch.dict(os.environ, {"FAKE_CODEX_AUTH": "api"}, clear=False):
        assert runtime.inspect().auth_mode == "chatgpt"
        refreshed = runtime.inspect(refresh=True)
    assert refreshed.auth_mode == "api_key"
    assert refreshed.ready is False


def test_preflight_rejects_missing_exec_capabilities(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"FAKE_CODEX_HELP_MISSING": "1"}, clear=False):
        inspected = runtime.inspect(refresh=True)
    assert inspected.ready is False
    assert inspected.capabilities_ok is False
    assert "--output-schema" in inspected.missing_capabilities


def test_timeout_kills_process_group(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path, timeout_seconds=0.2)
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "hang"}, clear=False):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert result.timed_out is True
    assert result.canceled is False
    assert result.return_code == -1
    assert "timed out" in (result.error or "")


def test_timeout_covers_a_child_that_never_reads_stdin(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(
        fake_codex,
        tmp_path,
        timeout_seconds=0.2,
        max_input_chars=1_000_000,
    )
    started = time.monotonic()
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "no_read"}, clear=False):
        result = runtime.run("x" * 900_000, SCHEMA)
    elapsed = time.monotonic() - started

    assert result.success is False
    assert result.timed_out is True
    assert elapsed < 2.0


def test_lingering_descendant_pipe_is_rejected_and_terminated(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    runtime = make_runtime(
        fake_codex,
        tmp_path,
        terminate_grace_seconds=0.1,
    )
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "linger"}, clear=False):
        result = runtime.run("prompt", SCHEMA)

    assert result.success is False
    assert result.stream_incomplete is True
    assert "streams did not reach EOF" in (result.error or "")


def test_cancel_event_kills_process_group(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path, timeout_seconds=5.0)
    cancel = threading.Event()

    def cancel_soon() -> None:
        time.sleep(0.1)
        cancel.set()

    thread = threading.Thread(target=cancel_soon, daemon=True)
    thread.start()
    with patch.dict(os.environ, {"FAKE_CODEX_MODE": "hang"}, clear=False):
        result = runtime.run("prompt", SCHEMA, cancel_event=cancel)

    assert result.success is False
    assert result.canceled is True
    assert result.timed_out is False
    assert result.return_code == -2


def test_already_canceled_does_not_run_preflight(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    cancel = threading.Event()
    cancel.set()
    with patch.object(runtime, "preflight", side_effect=AssertionError("must not run")):
        result = runtime.run("prompt", SCHEMA, cancel_event=cancel)

    assert result.canceled is True


def test_rejects_recursive_launch(fake_codex: Path, tmp_path: Path) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"SUPABASH_CODEX_CHILD": "1"}, clear=False):
        with pytest.raises(CodexRuntimeError, match="recursively"):
            runtime.run("prompt", SCHEMA)


def test_rejects_ambient_parent_codex_task_before_preflight(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(os.environ, {"CODEX_THREAD_ID": "parent-thread"}, clear=False), patch.object(
        runtime, "preflight", side_effect=AssertionError("preflight must not run")
    ):
        with pytest.raises(CodexRuntimeError, match="standalone terminal"):
            runtime.run("prompt", SCHEMA)


def test_child_environment_strips_parent_codex_and_openai_variables(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    capture_path = tmp_path / "capture-env.json"
    runtime = make_runtime(fake_codex, tmp_path)
    with patch.dict(
        os.environ,
        {
            "FAKE_CODEX_CAPTURE": str(capture_path),
            "CODEX_CI": "1",
            "CODEX_RANDOM_PARENT_SETTING": "private",
            "OPENAI_API_KEY": "should-not-reach-child",
        },
        clear=False,
    ):
        assert runtime.run("prompt", SCHEMA).success is True

    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    assert capture["codex_env"] == ["CODEX_HOME"]
    assert capture["openai_env"] == []


def test_ephemeral_mode_is_explicit_and_cannot_resume(
    fake_codex: Path,
    tmp_path: Path,
) -> None:
    capture_path = tmp_path / "capture.json"
    runtime = make_runtime(fake_codex, tmp_path, persistent_thread=False)
    with patch.dict(os.environ, {"FAKE_CODEX_CAPTURE": str(capture_path)}, clear=False):
        assert runtime.run("prompt", SCHEMA).success is True
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    assert "--ephemeral" in capture["argv"]
    with pytest.raises(ValueError, match="persistent_thread"):
        runtime.run("prompt", SCHEMA, thread_id="old-thread")


def test_prompt_limit_and_missing_executable(tmp_path: Path) -> None:
    runtime = CodexRuntime(
        CodexRuntimeConfig(
            command=str(tmp_path / "missing-codex"),
            cwd=tmp_path,
            max_input_chars=3,
            codex_home=tmp_path / "codex-home",
        )
    )
    with pytest.raises(ValueError, match="max_input_chars"):
        runtime.run("long", SCHEMA)
    inspected = runtime.inspect()
    assert inspected.installed is False
    assert inspected.ready is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_events", 1_001),
        ("max_event_chars", 32_769),
        ("max_stderr_chars", 262_145),
    ],
)
def test_runtime_rejects_capture_limits_above_hard_ceiling(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    values = {
        "command": "codex",
        "cwd": tmp_path,
        "codex_home": tmp_path / "codex-home",
        field: value,
    }
    with pytest.raises(ValueError, match=f"{field} must not exceed"):
        CodexRuntime(CodexRuntimeConfig(**values))
