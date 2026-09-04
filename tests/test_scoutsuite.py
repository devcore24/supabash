from unittest.mock import MagicMock, patch

from supabash.runner import CommandResult
from supabash.tools.scoutsuite import ScoutSuiteScanner


def test_scan_executes_registry_fallback_candidate(tmp_path):
    runner = MagicMock()
    runner.run.return_value = CommandResult(
        command="",
        return_code=0,
        stdout="",
        stderr="",
        success=True,
    )
    scanner = ScoutSuiteScanner(runner=runner)

    with patch(
        "supabash.tools.scoutsuite.resolve_tool_executable",
        return_value="/opt/bin/ScoutSuite",
    ) as resolve:
        result = scanner.scan(provider="aws", report_dir=str(tmp_path))

    assert result["success"] is True
    resolve.assert_called_once_with("scoutsuite", require_healthy=True)
    command = runner.run.call_args.args[0]
    assert command[0] == "/opt/bin/ScoutSuite"
    assert command[1:4] == ["aws", "--no-browser", "--report-dir"]


def test_scan_fails_before_runner_when_no_candidate_is_available(tmp_path):
    runner = MagicMock()
    scanner = ScoutSuiteScanner(runner=runner)

    with patch(
        "supabash.tools.scoutsuite.resolve_tool_executable",
        return_value=None,
    ):
        result = scanner.scan(provider="aws", report_dir=str(tmp_path))

    assert result["success"] is False
    assert "No compatible ScoutSuite executable" in result["error"]
    runner.run.assert_not_called()
