import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from supabash.codex_audit import (
    CodexAIAuditOrchestrator,
    CodexBackendUnavailable,
    CodexPlannerClient,
    build_codex_runtime_config,
)
from supabash.ai_audit import AIAuditOrchestrator
from supabash.codex_runtime import CodexPreflight, CodexRunResult
from supabash.codex_runtime import AMBIENT_CODEX_CONTEXT_VARS
from supabash.llm import ToolCallingError


def _preflight(*, ready=True):
    return CodexPreflight(
        command="/usr/bin/codex",
        installed=True,
        version="codex-cli 0.144.3",
        authenticated=ready,
        auth_mode="chatgpt" if ready else None,
        is_chatgpt=ready,
        ready=ready,
        error=None if ready else "Codex is not authenticated",
    )


def _result(
    output,
    *,
    thread_id="thread-1",
    events=(),
    policy_event_types=(),
    success=True,
    error=None,
    stderr="",
    canceled=False,
    timed_out=False,
    malformed_event_count=0,
    stdout_truncated=False,
):
    return CodexRunResult(
        success=success,
        return_code=0 if success else 1,
        thread_id=thread_id,
        structured_output=output,
        final_text=json.dumps(output) if output is not None else "",
        events=tuple(events),
        usage={"input_tokens": 12, "output_tokens": 4},
        stderr=stderr,
        error=error,
        timed_out=timed_out,
        canceled=canceled,
        duration_seconds=0.1,
        argv=("codex", "exec", "-"),
        malformed_event_count=malformed_event_count,
        stdout_truncated=stdout_truncated,
        stderr_truncated=False,
        policy_event_types=tuple(policy_event_types),
    )


class FakeRuntime:
    def __init__(self, results, *, preflight=None):
        self.results = list(results)
        self.inspection = preflight or _preflight()
        self.config = SimpleNamespace(
            sandbox="read-only",
            model="gpt-5-codex",
            ignore_user_config=True,
            disable_web_search=True,
            persistent_thread=False,
            max_input_chars=24000,
            max_events=500,
            max_event_chars=16384,
            max_stderr_chars=65536,
            disabled_features=(
                "plugins",
                "remote_plugin",
                "apps",
                "shell_tool",
                "browser_use",
                "computer_use",
                "in_app_browser",
                "image_generation",
                "multi_agent",
                "workspace_dependencies",
            ),
        )
        self.calls = []
        self.inspect_calls = []

    def inspect(self, *, refresh=False):
        self.inspect_calls.append(refresh)
        return self.inspection

    def run(self, prompt, output_schema, thread_id=None, cancel_event=None):
        self.calls.append(
            {
                "prompt": prompt,
                "output_schema": output_schema,
                "thread_id": thread_id,
                "cancel_event": cancel_event,
            }
        )
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture(autouse=True)
def clear_ambient_codex_context(monkeypatch):
    for key in AMBIENT_CODEX_CONTEXT_VARS:
        monkeypatch.delenv(key, raising=False)


def _client(runtime, *, persistent=True):
    runtime.config.persistent_thread = persistent
    return CodexPlannerClient(
        runtime=runtime,
        config={
            "codex": {
                "persistent_thread": persistent,
                "max_input_chars": 24000,
            }
        },
    )


def _tool_schema():
    return {
        "type": "function",
        "function": {
            "name": "propose_actions",
            "parameters": {
                "type": "object",
                "properties": {
                    "actions": {"type": "array", "items": {"type": "object"}},
                    "stop": {"type": "boolean"},
                    "notes": {"type": "string"},
                },
                "required": ["actions"],
                "additionalProperties": False,
            },
        },
    }


def test_planner_uses_structured_schema_and_resumes_thread():
    runtime = FakeRuntime(
        [
            _result({"actions": [], "stop": True, "notes": "enough evidence"}),
            _result({"summary": "No verified issue.", "findings": []}, thread_id="thread-1"),
        ]
    )
    client = _client(runtime)
    client.preflight()

    calls, meta = client.tool_call(
        [{"role": "system", "content": "Plan safely"}, {"role": "user", "content": "{}"}],
        tools=[_tool_schema()],
    )
    summary, _ = client.chat_with_meta(
        [{"role": "system", "content": "You are a security auditor."}, {"role": "user", "content": "{}"}]
    )

    assert calls == [
        {
            "id": None,
            "name": "propose_actions",
            "arguments": {"actions": [], "stop": True, "notes": "enough evidence"},
            "raw_arguments": {"actions": [], "stop": True, "notes": "enough evidence"},
        }
    ]
    assert meta["provider"] == "codex_cli"
    assert json.loads(summary)["findings"] == []
    assert runtime.calls[0]["thread_id"] is None
    assert runtime.calls[1]["thread_id"] == "thread-1"
    metadata = client.report_metadata()
    assert metadata["planner_attempt_count"] == 1
    assert metadata["planner_call_count"] == 1
    assert metadata["summary_call_count"] == 1
    strict_schema = runtime.calls[0]["output_schema"]
    assert strict_schema["additionalProperties"] is False
    assert strict_schema["required"] == ["actions", "stop", "notes"]
    assert strict_schema["properties"]["stop"]["type"] == ["boolean", "null"]


def test_prompt_is_redacted_and_marks_target_data_untrusted():
    runtime = FakeRuntime([_result({"actions": [], "stop": True, "notes": "done"})])
    client = _client(runtime)

    client.tool_call(
        [{"role": "user", "content": "Authorization: Bearer super-secret-token"}],
        tools=[_tool_schema()],
    )

    prompt = runtime.calls[0]["prompt"]
    assert "super-secret-token" not in prompt
    assert "<redacted>" in prompt
    assert "untrusted evidence" in prompt
    assert "Do not run shell commands" in prompt


@pytest.mark.parametrize("event_type", ["command_execution", "file_change", "mcp_tool_call", "web_search"])
def test_direct_codex_tool_activity_is_rejected(event_type):
    runtime = FakeRuntime(
        [
            _result(
                {"actions": [], "stop": True, "notes": "done"},
                events=(
                    {"type": "item.completed", "item": {"type": event_type, "command": "nmap target"}},
                ),
            )
        ]
    )
    client = _client(runtime)

    with pytest.raises(ToolCallingError, match="disallowed direct tool activity"):
        client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])

    assert event_type in client.planner_failure()
    assert event_type in client.policy_failure()
    assert client.report_metadata()["policy_violation"] is True


def test_streamed_policy_types_are_rejected_when_event_was_not_retained():
    runtime = FakeRuntime(
        [
            _result(
                {"actions": [], "stop": True, "notes": "done"},
                events=(),
                policy_event_types=("web_search",),
            )
        ]
    )
    client = _client(runtime)

    with pytest.raises(ToolCallingError, match="web_search"):
        client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])

    assert client.report_metadata()["policy_violation"] is True


def test_event_integrity_failure_is_fatal_policy_failure():
    runtime = FakeRuntime(
        [
            _result(
                {"actions": [], "stop": True, "notes": "done"},
                success=False,
                error="Codex emitted malformed JSONL",
                malformed_event_count=1,
            )
        ]
    )
    client = _client(runtime)

    with pytest.raises(ToolCallingError, match="malformed JSONL"):
        client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])

    assert client.policy_failure()
    assert client.report_metadata()["policy_integrity_failure"] is True


def test_runtime_failure_preserves_redacted_diagnostic_and_trace(tmp_path):
    runtime = FakeRuntime(
        [
            _result(
                None,
                success=False,
                error="Codex exited with status 1",
                stderr="Authorization: Bearer should-not-leak",
            )
        ]
    )
    client = _client(runtime)

    with pytest.raises(ToolCallingError, match="Codex exited"):
        client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])

    trace = tmp_path / "trace.jsonl"
    client.write_trace(trace)
    text = trace.read_text(encoding="utf-8")
    assert "should-not-leak" not in text
    assert '"error_present":true' in text
    assert client.report_metadata()["error"]


def test_runtime_exception_and_non_object_output_are_recorded_as_planner_failures():
    exception_client = _client(FakeRuntime([ValueError("token=runtime-secret")]))
    with pytest.raises(ToolCallingError):
        exception_client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])
    assert "runtime-secret" not in exception_client.planner_failure()
    assert exception_client.report_metadata()["error"]

    output_client = _client(FakeRuntime([_result([])]))
    with pytest.raises(ToolCallingError, match="no structured JSON object"):
        output_client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])
    assert "no structured JSON object" in output_client.planner_failure()


def test_canceled_planner_turn_is_not_reported_as_backend_failure():
    client = _client(
        FakeRuntime(
            [
                _result(
                    None,
                    success=False,
                    error="Codex run canceled.",
                    canceled=True,
                    malformed_event_count=1,
                    stdout_truncated=True,
                )
            ]
        )
    )

    with pytest.raises(ToolCallingError, match="canceled"):
        client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])

    assert client.planner_failure() == ""
    assert client.policy_failure() == ""
    metadata = client.report_metadata()
    assert metadata["error"] == ""
    assert metadata["planner_attempt_count"] == 1
    assert metadata["planner_call_count"] == 0


def test_large_prompt_keeps_conversation_json_well_formed():
    runtime = FakeRuntime([_result({"actions": [], "stop": True, "notes": "done"})])
    runtime.config.max_input_chars = 2000
    client = CodexPlannerClient(
        runtime=runtime,
        config={"codex": {"persistent_thread": False, "max_input_chars": 2000}},
    )
    client.tool_call(
        [{"role": "user", "content": "x" * 10000}],
        tools=[_tool_schema()],
    )
    conversation = runtime.calls[0]["prompt"].split("Conversation JSON:\n", 1)[1]
    assert isinstance(json.loads(conversation), list)


def test_client_preserves_supabash_tool_configuration_for_enforcement():
    runtime = FakeRuntime([])
    root_config = {
        "llm": {"enabled": False, "provider": "openai"},
        "codex": {"persistent_thread": False},
        "tools": {
            "nuclei": {
                "enabled": False,
                "timeout_seconds": 77,
                "rate_limit": 3,
            }
        },
    }
    client = CodexPlannerClient(runtime=runtime, config=root_config)
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)

    assert orchestrator._tool_config("nuclei") == {
        "enabled": False,
        "timeout_seconds": 77,
        "rate_limit": 3,
    }
    assert client.config.config["llm"]["enabled"] is True
    assert client.config.config["llm"]["provider"] == "openai"
    assert root_config["llm"]["enabled"] is False


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("sandbox", "danger-full-access", "sandbox=read-only"),
        ("ignore_user_config", False, "ignore_user_config=true"),
        ("disable_web_search", False, "disabled Codex web search"),
        ("disabled_features", (), "requires these disabled Codex features"),
        ("max_events", 1001, "1 <= max_events <= 1000"),
        ("max_event_chars", 32769, "1 <= max_event_chars <= 32768"),
        ("max_stderr_chars", 262145, "1 <= max_stderr_chars <= 262144"),
    ],
)
def test_injected_runtime_cannot_weaken_planner_boundary(field, value, expected):
    runtime = FakeRuntime([])
    setattr(runtime.config, field, value)
    with pytest.raises(ValueError, match=expected):
        CodexPlannerClient(runtime=runtime, config={"codex": {}})


def test_client_reports_effective_runtime_retention_not_separate_config():
    runtime = FakeRuntime([])
    runtime.config.persistent_thread = True
    client = CodexPlannerClient(
        runtime=runtime,
        config={"codex": {"persistent_thread": False}},
    )
    assert client.persistent_thread is True
    assert client.report_metadata()["session_retention"] == "codex_session_store"


def test_orchestrator_fails_preflight_before_running_baseline():
    runtime = FakeRuntime([], preflight=_preflight(ready=False))
    client = _client(runtime)
    orchestrator = CodexAIAuditOrchestrator(
        scanners={"sentinel": object()},
        codex_client=client,
    )

    with pytest.raises(CodexBackendUnavailable, match="not authenticated"):
        orchestrator.run("localhost", Path("unused.json"), consent=True)

    assert runtime.calls == []


def test_orchestrator_resets_target_state_and_refreshes_each_engagement():
    runtime = FakeRuntime([])
    client = _client(runtime)
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)
    client.thread_id = "old-target-thread"
    client.call_records.append({"operation": "planner", "ok": False, "error": "old failure"})
    client.trace_records.append({"target": "old-target"})

    with patch.object(AIAuditOrchestrator, "run", side_effect=[{"target": "one"}, {"target": "two"}]):
        assert orchestrator.run("one", None)["target"] == "one"
        assert client.thread_id is None
        assert client.call_records == []
        assert client.trace_records == []
        client.thread_id = "first-engagement-thread"
        client.call_records.append({"operation": "planner", "ok": True})
        assert orchestrator.run("two", None)["target"] == "two"

    assert client.thread_id is None
    assert client.call_records == []
    assert runtime.inspect_calls == [True, True]


def test_orchestrator_rejects_concurrent_reuse():
    orchestrator = CodexAIAuditOrchestrator(
        scanners={},
        codex_client=_client(FakeRuntime([])),
    )
    assert orchestrator._run_lock.acquire(blocking=False)
    try:
        with pytest.raises(CodexBackendUnavailable, match="already running"):
            orchestrator.run("localhost", None)
    finally:
        orchestrator._run_lock.release()


def test_orchestrator_rejects_ambient_codex_context_before_preflight(monkeypatch):
    runtime = FakeRuntime([])
    client = _client(runtime)
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)
    monkeypatch.setenv("CODEX_THREAD_ID", "parent-thread")

    with pytest.raises(CodexBackendUnavailable, match="standalone terminal"):
        orchestrator.run("localhost", None)

    assert runtime.inspect_calls == []


def test_policy_violation_in_summary_marks_report_failed():
    client = _client(
        FakeRuntime(
            [
                _result(
                    {"summary": "ignored", "findings": []},
                    policy_event_types=("web_search",),
                )
            ]
        )
    )
    with pytest.raises(ToolCallingError):
        client.chat_with_meta([{"role": "system", "content": "security auditor"}])
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)
    agg = {
        "target": "localhost",
        "report_kind": "ai_audit",
        "ai_audit": {"planner": {}},
    }
    with patch.object(AIAuditOrchestrator, "_persist_final_report", return_value=agg):
        orchestrator._persist_final_report(agg, None)
    assert "policy enforcement failed" in agg["run_error"]


def test_non_policy_summary_failure_marks_report_failed():
    client = _client(
        FakeRuntime(
            [
                _result(
                    None,
                    success=False,
                    error="Codex service unavailable",
                )
            ]
        )
    )
    with pytest.raises(ToolCallingError):
        client.chat_with_meta([{"role": "system", "content": "security auditor"}])
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)
    agg = {
        "target": "localhost",
        "report_kind": "ai_audit",
        "ai_audit": {"planner": {}},
    }
    with patch.object(AIAuditOrchestrator, "_persist_final_report", return_value=agg):
        orchestrator._persist_final_report(agg, None)
    assert agg["run_error"] == "Codex summary operation failed: Codex service unavailable"


def test_trace_write_failure_is_visible_and_fails_report(tmp_path):
    client = _client(FakeRuntime([]))
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)
    agg = {"target": "localhost", "ai_audit": {"planner": {}}}
    output = tmp_path / "report.json"
    with patch.object(AIAuditOrchestrator, "_attach_report_artifacts", return_value=None), patch.object(
        client, "write_trace", side_effect=OSError("disk full")
    ):
        orchestrator._attach_report_artifacts(agg, output)
    assert agg["codex_agent"]["trace_error"] == "disk full"
    assert agg["run_error"] == "Codex trace persistence failed"


def test_outputless_report_keeps_codex_backend_attribution():
    client = _client(FakeRuntime([]))
    orchestrator = CodexAIAuditOrchestrator(scanners={}, codex_client=client)
    agg = {
        "target": "localhost",
        "report_kind": "ai_audit",
        "ai_audit": {"planner": {"type": "tool_calling"}},
    }
    with patch.object(AIAuditOrchestrator, "_persist_final_report", return_value=agg):
        result = orchestrator._persist_final_report(agg, None)

    assert result["codex_agent"]["backend"] == "codex_cli"
    assert result["ai_audit"]["planner"]["type"] == "codex_cli"
    assert result["ai_audit"]["agent_backend"] == "codex"


def test_trace_omits_event_payloads_and_is_engagement_bounded(tmp_path):
    runtime = FakeRuntime(
        [
            _result(
                {"actions": [], "stop": True, "notes": "done"},
                events=(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "command_execution",
                            "command": "echo proprietary-secret-value",
                            "aggregated_output": "proprietary-secret-value",
                        },
                    },
                ),
            )
        ]
    )
    client = _client(runtime)
    with pytest.raises(ToolCallingError):
        client.tool_call([{"role": "user", "content": "{}"}], tools=[_tool_schema()])

    trace = tmp_path / "trace.jsonl"
    metadata = client.write_trace(trace)
    trace_text = trace.read_text(encoding="utf-8")
    assert "proprietary-secret-value" not in trace_text
    assert "command_execution" in trace_text
    assert metadata["size_bytes"] <= 4 * 1024 * 1024


def test_runtime_builder_uses_private_empty_ephemeral_workspace(tmp_path):
    with patch.dict(os.environ, {"XDG_CACHE_HOME": str(tmp_path)}, clear=False):
        runtime_config = build_codex_runtime_config({"codex": {}})

    workspace = Path(runtime_config.cwd)
    assert workspace.is_dir()
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
    assert list(workspace.iterdir()) == []
    assert runtime_config.persistent_thread is False
    assert runtime_config.disable_web_search is True


@pytest.mark.parametrize(
    "codex_config, expected",
    [
        ({"sandbox": "workspace-write"}, "sandbox=read-only"),
        ({"ignore_user_config": False}, "ignore_user_config=true"),
        ({"disabled_features": []}, "requires these disabled Codex features"),
    ],
)
def test_runtime_builder_rejects_weakened_planner_boundaries(codex_config, expected):
    with pytest.raises(ValueError, match=expected):
        build_codex_runtime_config({"codex": codex_config})


def test_runtime_builder_rejects_ambient_workspace_content(tmp_path):
    with patch.dict(os.environ, {"XDG_CACHE_HOME": str(tmp_path)}, clear=False):
        runtime_config = build_codex_runtime_config({"codex": {}})
        Path(runtime_config.cwd, "AGENTS.md").write_text("ambient instructions", encoding="utf-8")
        with pytest.raises(ValueError, match="must be empty"):
            build_codex_runtime_config({"codex": {}})


def test_workspace_os_error_is_wrapped_as_backend_unavailable():
    with patch(
        "supabash.codex_audit._private_codex_workspace",
        side_effect=PermissionError("cache is read-only"),
    ):
        with pytest.raises(CodexBackendUnavailable, match="cache is read-only"):
            CodexAIAuditOrchestrator(scanners={}, config={"codex": {}})
