from unittest.mock import MagicMock, patch

from supabash.runner import CommandResult
from supabash.tools.theharvester import TheHarvesterScanner


def test_scan_executes_registry_fallback_candidate():
    runner = MagicMock()
    runner.run.return_value = CommandResult(
        command="",
        return_code=0,
        stdout="",
        stderr="",
        success=True,
    )
    scanner = TheHarvesterScanner(runner=runner)

    with patch(
        "supabash.tools.theharvester.resolve_tool_executable",
        return_value="/opt/bin/theharvester",
    ) as resolve:
        result = scanner.scan("example.com", sources="crtsh")

    assert result["success"] is True
    resolve.assert_called_once_with("theharvester", require_healthy=True)
    command = runner.run.call_args.args[0]
    assert command[0] == "/opt/bin/theharvester"
    assert command[1:5] == ["-d", "example.com", "-b", "crtsh"]


def test_scan_fails_before_runner_when_no_candidate_is_available():
    runner = MagicMock()
    scanner = TheHarvesterScanner(runner=runner)

    with patch(
        "supabash.tools.theharvester.resolve_tool_executable",
        return_value=None,
    ):
        result = scanner.scan("example.com", sources="crtsh")

    assert result["success"] is False
    assert "No compatible theHarvester executable" in result["error"]
    runner.run.assert_not_called()
