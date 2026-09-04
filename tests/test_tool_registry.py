import copy
import importlib
import json
import os
import re
import unittest
from importlib import resources
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from supabash.audit import AuditOrchestrator
from supabash.config import DEFAULT_CONFIG
from tests.test_artifacts import artifact_path, cleanup_artifact
from supabash.tool_registry import (
    TOOL_SPEC_RESOURCE,
    TOOL_SPEC_SCHEMA_VERSION,
    ToolRegistryError,
    load_tool_registry,
    parse_tool_registry,
    probe_executable_health,
    python_distribution_version,
    resolve_best_executable,
    resolve_executable,
    resolve_executable_candidates,
    resolve_healthy_executable,
    resolve_tool_executable,
    version_commands_for_tool,
)


EXPECTED_WRAPPERS = {
    "aircrack_ng": "supabash.tools.aircrack_ng:AircrackNgScanner",
    "browser_use": "supabash.tools.browser_use:BrowserUseScanner",
    "crackmapexec": "supabash.tools.crackmapexec:CrackMapExecScanner",
    "dnsenum": "supabash.tools.dnsenum:DnsenumScanner",
    "enum4linux_ng": "supabash.tools.enum4linux_ng:Enum4linuxNgScanner",
    "ffuf": "supabash.tools.ffuf:FfufScanner",
    "gobuster": "supabash.tools.gobuster:GobusterScanner",
    "httpx": "supabash.tools.httpx:HttpxScanner",
    "hydra": "supabash.tools.hydra:HydraRunner",
    "katana": "supabash.tools.katana:KatanaScanner",
    "masscan": "supabash.tools.masscan:MasscanScanner",
    "medusa": "supabash.tools.medusa:MedusaRunner",
    "netdiscover": "supabash.tools.netdiscover:NetdiscoverScanner",
    "nikto": "supabash.tools.nikto:NiktoScanner",
    "nmap": "supabash.tools.nmap:NmapScanner",
    "nuclei": "supabash.tools.nuclei:NucleiScanner",
    "prowler": "supabash.tools.prowler:ProwlerScanner",
    "rustscan": "supabash.tools.rustscan:RustscanScanner",
    "scoutsuite": "supabash.tools.scoutsuite:ScoutSuiteScanner",
    "searchsploit": "supabash.tools.searchsploit:SearchsploitScanner",
    "sqlmap": "supabash.tools.sqlmap:SqlmapScanner",
    "sslscan": "supabash.tools.sslscan:SslscanScanner",
    "subfinder": "supabash.tools.subfinder:SubfinderScanner",
    "supabase_audit": "supabash.tools.supabase_audit:SupabaseAuditScanner",
    "theharvester": "supabash.tools.theharvester:TheHarvesterScanner",
    "trivy": "supabash.tools.trivy:TrivyScanner",
    "whatweb": "supabash.tools.whatweb:WhatWebScanner",
    "wpscan": "supabash.tools.wpscan:WPScanScanner",
}


EXPECTED_RECOMMENDED_VERSIONS = {
    "browser_use": "0.13.7",
    "crackmapexec": "1.5.1",
    "enum4linux_ng": "1.3.10",
    "httpx": "1.10.0",
    "katana": "1.6.1",
    "nuclei": "3.11.0",
    "prowler": "5.36.0",
    "rustscan": "2.4.1",
    "subfinder": "2.14.0",
    "theharvester": "4.11.1",
    "trivy": "0.73.0",
    "wpscan": "4.1.0",
}


def _manifest_payload():
    text = resources.files("supabash").joinpath(TOOL_SPEC_RESOURCE).read_text(encoding="utf-8")
    return json.loads(text)


def test_builtin_registry_covers_every_current_wrapper_and_imports():
    registry = load_tool_registry()

    assert registry.schema_version == TOOL_SPEC_SCHEMA_VERSION
    assert {spec.id: spec.wrapper for spec in registry.tools} == EXPECTED_WRAPPERS
    for wrapper in EXPECTED_WRAPPERS.values():
        module_name, class_name = wrapper.split(":", 1)
        assert getattr(importlib.import_module(module_name), class_name)


def test_registry_aliases_and_version_commands_are_rendered():
    registry = load_tool_registry()

    assert registry.require("enum4linux-ng").id == "enum4linux_ng"
    assert registry.require("netexec").id == "crackmapexec"
    assert registry.require("browser-use").id == "browser_use"
    assert version_commands_for_tool("netexec", executable="/opt/bin/nxc") == (
        ("/opt/bin/nxc", "--version"),
    )
    assert version_commands_for_tool("supabase_audit") == ()


def test_httpx_resolution_prefers_projectdiscovery_system_binary_over_python_cli():
    registry = load_tool_registry()
    executable = registry.require("httpx").primary_executable
    assert executable is not None
    assert executable.candidates == (
        "/usr/local/bin/httpx",
        "/usr/bin/httpx",
        "httpx",
    )

    paths = {
        "/usr/local/bin/httpx": "/usr/local/bin/httpx",
        "httpx": "/project/venv/bin/httpx",
    }
    fake_which = paths.get

    assert resolve_executable_candidates(executable, which=fake_which) == (
        ("/usr/local/bin/httpx", "/usr/local/bin/httpx"),
        ("/usr/bin/httpx", None),
        ("httpx", "/project/venv/bin/httpx"),
    )
    assert resolve_executable(executable, which=fake_which) == "/usr/local/bin/httpx"
    assert (
        resolve_tool_executable("httpx", registry=registry, which=fake_which)
        == "/usr/local/bin/httpx"
    )


def test_healthy_resolution_skips_wrong_or_broken_shadow_candidate():
    registry = load_tool_registry()
    executable = registry.require("httpx").primary_executable
    assert executable is not None
    paths = {
        "/usr/local/bin/httpx": "/opt/shadow/httpx",
        "httpx": "/opt/projectdiscovery/httpx",
    }

    def fake_run(command, **_kwargs):
        if command[0] == "/opt/shadow/httpx":
            return SimpleNamespace(
                returncode=2,
                stdout="Usage: httpx [OPTIONS] URL\n",
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="httpx version v1.10.0\n", stderr="")

    assert (
        resolve_healthy_executable(executable, which=paths.get, run=fake_run)
        == "/opt/projectdiscovery/httpx"
    )
    assert (
        resolve_tool_executable(
            "httpx",
            registry=registry,
            which=paths.get,
            require_healthy=True,
            run=fake_run,
        )
        == "/opt/projectdiscovery/httpx"
    )


def test_runtime_resolution_prefers_compatible_version_like_deep_doctor():
    registry = load_tool_registry()
    executable = registry.require("httpx").primary_executable
    assert executable is not None
    paths = {
        "/usr/local/bin/httpx": "/opt/old/httpx",
        "httpx": "/opt/current/httpx",
    }

    def fake_run(command, **_kwargs):
        version = "1.8.1" if command[0] == "/opt/old/httpx" else "1.10.0"
        return SimpleNamespace(
            returncode=0,
            stdout=f"httpx version v{version}\n",
            stderr="",
        )

    resolution = resolve_best_executable(
        executable,
        recommended_version="1.10.0",
        tool_names=("httpx",),
        which=paths.get,
        run=fake_run,
    )

    assert resolution.healthy_path == "/opt/current/httpx"
    assert [item.version_status for item in resolution.evaluations] == [
        "outdated",
        "recommended",
    ]
    assert (
        resolve_tool_executable(
            "httpx",
            registry=registry,
            which=paths.get,
            require_healthy=True,
            run=fake_run,
        )
        == "/opt/current/httpx"
    )


def test_healthy_resolution_fails_closed_for_python_httpx_only():
    executable = load_tool_registry().require("httpx").primary_executable
    assert executable is not None

    def fake_which(candidate):
        return "/project/venv/bin/httpx" if candidate == "httpx" else None

    def fake_run(_command, **_kwargs):
        return SimpleNamespace(
            returncode=2,
            stdout="Usage: httpx [OPTIONS] URL\n",
            stderr="",
        )

    assert resolve_healthy_executable(executable, which=fake_which, run=fake_run) is None


def test_resolution_rejects_relative_path_results():
    executable = load_tool_registry().require("httpx").primary_executable
    assert executable is not None
    assert (
        resolve_executable(
            executable,
            which=lambda candidate: "./httpx" if candidate == "httpx" else None,
        )
        is None
    )


def test_health_probe_rejects_fatal_marker_even_with_success_exit():
    executable = load_tool_registry().require("httpx").primary_executable
    assert executable is not None
    result = probe_executable_health(
        executable,
        "/usr/local/bin/httpx",
        run=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="Traceback (most recent call last):\nModuleNotFoundError: broken\n",
            stderr="",
        ),
    )

    assert not result.ok
    assert result.fatal_marker == "traceback (most recent call last)"


def test_registry_versions_and_default_config_stay_synchronized():
    registry = load_tool_registry()

    actual_versions = {
        spec.id: spec.recommended_version
        for spec in registry.tools
        if spec.recommended_version is not None
    }
    assert actual_versions == EXPECTED_RECOMMENDED_VERSIONS

    config_tools = DEFAULT_CONFIG["tools"]
    for spec in registry.tools:
        assert spec.config_key in config_tools
        assert config_tools[spec.config_key]["enabled"] is spec.default_enabled


def test_external_executable_groups_have_version_and_health_probes():
    registry = load_tool_registry()

    external = [spec for spec in registry.tools if spec.install_method != "internal"]
    assert external
    for spec in external:
        assert spec.executables, spec.id
        for executable in spec.executables:
            assert executable.candidates, (spec.id, executable.id)
            if spec.id != "searchsploit" and not executable.python_distribution:
                assert executable.version_commands, (spec.id, executable.id)
            assert executable.health_probe is not None, (spec.id, executable.id)


def test_evidence_version_lookup_uses_registry_alias_candidates(monkeypatch):
    orchestrator = AuditOrchestrator(scanners={}, llm_client=None)
    monkeypatch.setattr("supabash.audit.shutil.which", lambda candidate: "/usr/bin/nxc" if candidate == "nxc" else None)

    assert orchestrator._version_commands_for_tool("crackmapexec") == [
        ["/usr/bin/nxc", "--version"]
    ]
    assert orchestrator._version_commands_for_tool("searchsploit") == []


def test_python_distribution_version_uses_entrypoint_interpreter_without_secret_env(tmp_path):
    interpreter = tmp_path / "python"
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)
    entrypoint = tmp_path / "browser-use"
    entrypoint.write_text(f"#!{interpreter}\n", encoding="utf-8")
    entrypoint.chmod(0o755)

    completed = SimpleNamespace(returncode=0, stdout="0.13.7\n", stderr="")
    with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "do-not-copy"}), patch(
        "supabash.tool_registry.subprocess.run", return_value=completed
    ) as run:
        assert python_distribution_version(str(entrypoint), "browser-use") == "0.13.7"

    kwargs = run.call_args.kwargs
    assert "AWS_SECRET_ACCESS_KEY" not in kwargs["env"]
    assert run.call_args.args[0][0] == str(interpreter)
    assert run.call_args.args[0][-1] == "browser-use"


def test_evidence_version_lookup_uses_python_distribution_probe(monkeypatch):
    orchestrator = AuditOrchestrator(scanners={}, llm_client=None)
    monkeypatch.setattr(
        "supabash.audit.shutil.which",
        lambda candidate: "/opt/pipx/browser-use" if candidate == "browser-use" else None,
    )
    calls = []

    def fake_distribution_version(executable, distribution, **_kwargs):
        calls.append((executable, distribution))
        return "0.12.1"

    monkeypatch.setattr(
        "supabash.audit.python_distribution_version", fake_distribution_version
    )

    assert orchestrator._best_effort_tool_version("browser_use") == "0.12.1"
    assert calls == [("/opt/pipx/browser-use", "browser-use")]


def test_evidence_version_lookup_does_not_run_prowler_network_version_command(monkeypatch):
    orchestrator = AuditOrchestrator(scanners={}, llm_client=None)
    monkeypatch.setattr(
        "supabash.audit.shutil.which",
        lambda candidate: "/opt/pipx/prowler" if candidate == "prowler" else None,
    )
    calls = []

    def fake_distribution_version(executable, distribution, **_kwargs):
        calls.append((executable, distribution))
        return "5.36.0"

    monkeypatch.setattr(
        "supabash.audit.python_distribution_version", fake_distribution_version
    )

    assert orchestrator._version_commands_for_tool("prowler") == []
    assert orchestrator._best_effort_tool_version("prowler") == "5.36.0"
    assert calls == [("/opt/pipx/prowler", "prowler")]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload.update(schema_version=999), "unsupported value 999"),
        (
            lambda payload: payload["tools"][1].update(aliases=["nmap"]),
            "duplicate tool id/alias",
        ),
        (
            lambda payload: payload["tools"][0]["executables"][0].update(
                version_commands=[["nmap", "--version"]]
            ),
            "must start with the {executable} placeholder",
        ),
        (
            lambda payload: payload["tools"][0].update(unexpected=True),
            "unknown field(s): unexpected",
        ),
        (
            lambda payload: payload["tools"][0]["executables"][0].update(
                candidates=["nmap;unexpected-command"]
            ),
            "must be a safe executable name",
        ),
    ],
)
def test_registry_validation_fails_closed(mutate, message):
    payload = copy.deepcopy(_manifest_payload())
    mutate(payload)

    with pytest.raises(ToolRegistryError, match=re.escape(message)):
        parse_tool_registry(payload, source="test-manifest")


class DummyConfigManager:
    def __init__(self, tools_cfg):
        self.config = {
            "llm": {"max_input_chars": 12000},
            "tools": tools_cfg,
        }


class FakeLLM:
    def __init__(self, cfg):
        self.config = cfg

    def chat(self, messages, temperature=0.2):
        return json.dumps({"summary": "ok", "findings": []})


class SpyScanner:
    def __init__(self, name, result=None):
        self.name = name
        self.calls = 0
        self.result = result if result is not None else {"success": True, "scan_data": {"hosts": []}}

    def scan(self, *args, **kwargs):
        self.calls += 1
        return self.result


class TestToolRegistryExecutionBoundary(unittest.TestCase):
    def test_disabled_tool_is_skipped(self):
        nmap = SpyScanner(
            "nmap",
            result={
                "success": True,
                "scan_data": {
                    "hosts": [
                        {"ports": [{"port": 80, "protocol": "tcp", "service": "http", "state": "open"}]},
                    ]
                },
            },
        )
        whatweb = SpyScanner("whatweb", result={"success": True, "scan_data": []})
        nuclei = SpyScanner("nuclei", result={"success": True, "findings": []})
        gobuster = SpyScanner("gobuster", result={"success": True, "findings": []})

        cfg = DummyConfigManager(tools_cfg={"whatweb": {"enabled": False}})
        orch = AuditOrchestrator(
            scanners={
                "nmap": nmap,
                "whatweb": whatweb,
                "nuclei": nuclei,
                "gobuster": gobuster,
                "sqlmap": SpyScanner("sqlmap"),
                "nikto": SpyScanner("nikto"),
                "sslscan": SpyScanner("sslscan"),
                "dnsenum": SpyScanner("dnsenum"),
                "enum4linux-ng": SpyScanner("enum4linux-ng"),
                "trivy": SpyScanner("trivy"),
                "supabase_audit": SpyScanner("supabase_audit"),
            },
            llm_client=FakeLLM(cfg),
        )

        out = artifact_path("tool_registry_test.json")
        report = orch.run("example.com", out)
        self.assertTrue(out.exists())
        cleanup_artifact(out)

        self.assertEqual(nmap.calls, 1)
        self.assertEqual(whatweb.calls, 0)

        entry = next((e for e in report.get("results", []) if e.get("tool") == "whatweb"), None)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.get("skipped"))


if __name__ == "__main__":
    unittest.main()
