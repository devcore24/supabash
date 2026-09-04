from unittest.mock import MagicMock, patch

from supabash.runner import CommandResult
from supabash.tools.crackmapexec import CrackMapExecScanner


def test_scan_executes_registry_fallback_candidate():
    runner = MagicMock()
    runner.run.return_value = CommandResult(
        command="",
        return_code=0,
        stdout="SMB result",
        stderr="",
        success=True,
    )
    scanner = CrackMapExecScanner(runner=runner)

    with patch(
        "supabash.tools.crackmapexec.resolve_tool_executable",
        return_value="/home/test/.local/bin/nxc",
    ) as resolve:
        result = scanner.scan("10.0.0.5", protocol="smb")

    assert result["success"] is True
    resolve.assert_called_once_with("crackmapexec", require_healthy=True)
    command = runner.run.call_args.args[0]
    assert command[:3] == ["/home/test/.local/bin/nxc", "smb", "10.0.0.5"]


def test_scan_fails_before_runner_when_no_healthy_candidate_exists():
    runner = MagicMock()
    scanner = CrackMapExecScanner(runner=runner)

    with patch(
        "supabash.tools.crackmapexec.resolve_tool_executable",
        return_value=None,
    ):
        result = scanner.scan("10.0.0.5")

    assert result["success"] is False
    assert "No compatible NetExec/CrackMapExec executable" in result["error"]
    runner.run.assert_not_called()
