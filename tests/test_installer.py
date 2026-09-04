from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPOSITORY_ROOT / "install.sh"


def _write_installer_manifest(
    path: Path,
    *,
    tool_id: str,
    executable: str,
    doctor_required: bool = False,
    recommended_version: str | None = None,
    argv_suffix: tuple[str, ...] = ("--version",),
    success_exit_codes: tuple[int, ...] = (0,),
    candidates: tuple[str, ...] | None = None,
) -> None:
    payload = {
        "schema_version": 1,
        "registry_version": "installer-test",
        "tools": [
            {
                "id": tool_id,
                "wrapper": "supabash.tools.nmap:NmapTool",
                "config_key": tool_id,
                "aliases": [],
                "description": "Installer test tool",
                "target_kinds": ["test"],
                "default_enabled": False,
                "doctor_required": doctor_required,
                "recommended_version": recommended_version,
                "install_method": "system_package",
                "privileges": [],
                "datasets": [],
                "credentials": [],
                "executables": [
                    {
                        "id": "primary",
                        "candidates": list(candidates or (executable,)),
                        "required": True,
                        "doctor_check": doctor_required,
                        "doctor_name": f"bin:{executable}",
                        "doctor_required": doctor_required,
                        "version_commands": [["{executable}", *argv_suffix]],
                        "health_probe": {
                            "argv": ["{executable}", *argv_suffix],
                            "success_exit_codes": list(success_exit_codes),
                            "timeout_seconds": 2,
                        },
                        "python_distribution": None,
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    child_env = dict(os.environ)
    if env:
        child_env.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=REPOSITORY_ROOT,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_installer_can_be_sourced_without_running_main() -> None:
    result = _bash(f"source {INSTALLER!s}; printf '%s' sourced")

    assert result.returncode == 0, result.stderr
    assert result.stdout == "sourced"


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_projectdiscovery_release_patterns_match_current_asset_names() -> None:
    script = f"""
source {INSTALLER!s}
release_json='{{"assets":[
  {{"name":"nuclei_3.11.0_linux_amd64.zip","browser_download_url":"nuclei-url"}},
  {{"name":"httpx_1.10.0_linux_amd64.zip","browser_download_url":"httpx-url"}},
  {{"name":"subfinder_2.14.0_linux_arm64.zip","browser_download_url":"subfinder-url"}},
  {{"name":"katana_1.6.1_linux_amd64.zip","browser_download_url":"katana-url"}}
]}}'
test "$(pick_release_asset_url "$release_json" '^nuclei_.*_linux_amd64\\.zip$')" = nuclei-url
test "$(pick_release_asset_url "$release_json" '^httpx_.*_linux_amd64\\.zip$')" = httpx-url
test "$(pick_release_asset_url "$release_json" '^subfinder_.*_linux_arm64\\.zip$')" = subfinder-url
test "$(pick_release_asset_url "$release_json" '^katana_.*_linux_amd64\\.zip$')" = katana-url
"""
    result = _bash(script)

    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_installer_versions_are_loaded_from_tool_spec_manifest() -> None:
    script = f"""
source {INSTALLER!s}
load_tool_versions
printf '%s\n' "$NUCLEI_VERSION|$HTTPX_VERSION|$SUBFINDER_VERSION|$KATANA_VERSION|$TRIVY_VERSION|$THEHARVESTER_VERSION|$PROWLER_VERSION|$BROWSER_USE_VERSION|$WPSCAN_VERSION"
"""
    result = _bash(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "3.11.0|1.10.0|2.14.0|1.6.1|0.73.0|4.11.1|5.36.0|0.13.7|4.1.0"
    )


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
@pytest.mark.parametrize(
    "registry_entrypoint",
    [
        "validate_tool_spec_manifest",
        "tool_recommended_version nuclei",
        "tool_registry_health_check nuclei /bin/true",
        "verify_required_tool_health",
        "load_tool_versions",
        "install_trivy_release",
    ],
)
def test_installer_registry_entrypoints_fail_closed_on_invalid_manifest(
    tmp_path: Path,
    registry_entrypoint: str,
) -> None:
    manifest = tmp_path / "invalid-tools.json"
    manifest.write_text('{"schema_version":1,"tools":[', encoding="utf-8")
    result = _bash(
        f"source {INSTALLER!s}; {registry_entrypoint}",
        env={"TOOL_SPEC_MANIFEST": str(manifest)},
    )

    assert result.returncode != 0
    assert "ToolSpec registry failed installer validation" in result.stdout


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_installer_rejects_structurally_incomplete_tool_spec_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "empty-tools.json"
    manifest.write_text(
        '{"schema_version":1,"registry_version":"test","tools":[]}',
        encoding="utf-8",
    )
    result = _bash(
        f"source {INSTALLER!s}; validate_tool_spec_manifest",
        env={"TOOL_SPEC_MANIFEST": str(manifest)},
    )

    assert result.returncode != 0
    assert "ToolSpec registry failed installer validation" in result.stdout


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_installer_uses_the_strict_python_tool_spec_schema(tmp_path: Path) -> None:
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="schema-test",
        executable="schema-test",
    )
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    del payload["tools"][0]["wrapper"]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    result = _bash(
        f"source {INSTALLER!s}; validate_tool_spec_manifest",
        env={"TOOL_SPEC_MANIFEST": str(manifest)},
    )

    assert result.returncode != 0
    assert "ToolSpec registry failed installer validation" in result.stdout


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_installer_resolves_executables_in_tool_spec_order(tmp_path: Path) -> None:
    preferred = tmp_path / "project-httpx"
    shadow = tmp_path / "httpx"
    preferred.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    preferred.chmod(0o755)
    shadow.chmod(0o755)
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="httpx",
        executable="httpx",
        candidates=("project-httpx", "httpx"),
    )

    result = _bash(
        f"source {INSTALLER!s}; tool_registry_resolve_executable httpx",
        env={
            "TOOL_SPEC_MANIFEST": str(manifest),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(preferred)


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_installer_executable_resolution_rejects_directories(tmp_path: Path) -> None:
    directory_candidate = tmp_path / "directory-tool"
    directory_candidate.mkdir()
    fallback = tmp_path / "fallback-tool"
    fallback.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fallback.chmod(0o755)
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="directory-resolution-test",
        executable="directory-tool",
        candidates=("directory-tool", "fallback-tool"),
    )
    script = f"""
source {INSTALLER!s}
command() {{
  if [ "$1" = -v ] && [ "$2" = directory-tool ]; then
    printf '%s\n' "$DIRECTORY_CANDIDATE"
    return 0
  fi
  builtin command "$@"
}}
tool_registry_resolve_executable directory-resolution-test
"""
    result = _bash(
        script,
        env={
            "DIRECTORY_CANDIDATE": str(directory_candidate),
            "TOOL_SPEC_MANIFEST": str(manifest),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(fallback)


def test_generated_runner_does_not_activate_venv_or_shadow_scanner_tools() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    runner_script = (REPOSITORY_ROOT / "supabash_runner").read_text(encoding="utf-8")

    assert 'source "\\$DIR/venv/bin/activate"' not in installer
    assert 'exec "\\$DIR/venv/bin/python" -m supabash "\\$@"' in installer
    assert 'source "$DIR/venv/bin/activate"' not in runner_script
    assert 'exec "$DIR/venv/bin/python" -m supabash "$@"' in runner_script


def test_installer_rejects_unsafe_version_override() -> None:
    result = _bash(
        f"source {INSTALLER!s}; load_tool_versions",
        env={"BROWSER_USE_VERSION": "0.13.7'; unexpected-command '"},
    )

    assert result.returncode != 0
    assert "Invalid version value in BROWSER_USE_VERSION" in result.stdout


def test_codex_setup_check_detects_chatgpt_login_without_installing() -> None:
    script = f"""
source {INSTALLER!s}
invoking_user_has_command() {{ test "$1" = codex; }}
run_as_invoking_user_shell() {{
  case "$1" in
    "codex --version") printf '%s\n' 'codex-cli 0.146.0' ;;
    "codex login status") printf '%s\n' 'Logged in using ChatGPT' ;;
    *) return 20 ;;
  esac
}}
check_codex_setup
"""
    result = _bash(script)

    assert result.returncode == 0, result.stderr
    assert "Codex CLI detected (codex-cli 0.146.0)" in result.stdout
    assert "Codex is authenticated with ChatGPT" in result.stdout


def test_netexec_install_is_pinned_to_upstream_tag_not_nonexistent_pypi_package() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert "NetExec.git@${netexec_ref}" in installer
    assert 'netexec==${NETEXEC_VERSION}' not in installer


def test_installer_logs_use_unpredictable_mktemp_paths() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert ">/tmp/${name}-go-install.log" not in installer
    assert ">/tmp/supabash-browser-use-install.log" not in installer
    assert "supabash-${name}-go.XXXXXX.log" in installer
    assert "supabash-browser-use.XXXXXX.log" in installer


def test_versioned_non_pypi_installs_never_fall_back_to_mutable_branches() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert 'for ref in "$ENUM4LINUX_NG_VERSION" "main" "master"' not in installer
    assert 'enum_ref="v${enum_ref}"' in installer
    assert 'gem install wpscan -v "$WPSCAN_VERSION"' in installer
    assert "trivy_${release_version}_checksums.txt" in installer


def test_fresh_installs_do_not_seed_versioned_tools_from_distro_packages() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    apt_block = installer.split("DEPENDENCIES=(", 1)[1].split(")", 1)[0]

    for tool in ("rustscan", "theharvester", "wpscan"):
        assert tool not in apt_block
    assert 'Installing RustScan from its tested GitHub release' in installer
    assert 'gem install wpscan -v "$WPSCAN_VERSION"' in installer


def test_optional_versioned_install_paths_share_the_registry_health_gate() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    for invocation in (
        'should_retain_existing_tool trivy "$existing_path" Trivy',
        'should_retain_existing_tool rustscan "$rustscan_path" RustScan',
        'should_retain_existing_tool wpscan "$wpscan_path" WPScan',
        'should_retain_existing_tool theharvester "$theharvester_path" theHarvester 1',
        'should_retain_existing_tool crackmapexec "$netexec_path" "CrackMapExec/NetExec" 1',
        'should_retain_existing_tool prowler "$prowler_path" Prowler 1',
        'should_retain_existing_tool browser_use "$browser_path" browser-use 1',
        'should_retain_existing_tool enum4linux_ng "$enum4linux_path" enum4linux-ng',
    ):
        assert invocation in installer


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_existing_healthy_optional_tool_is_retained_without_download(tmp_path: Path) -> None:
    executable = tmp_path / "trivy"
    executable.write_text("#!/bin/sh\nprintf '%s\\n' 'Version: 0.73.0'\n", encoding="utf-8")
    executable.chmod(0o755)
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="trivy",
        executable="trivy",
        recommended_version="0.73.0",
    )
    marker = tmp_path / "download-attempted"
    script = f"""
source {INSTALLER!s}
TRIVY_VERSION=0.73.0
download_url_to_tmp() {{ printf attempted > "$DOWNLOAD_MARKER"; return 1; }}
install_trivy_release
test ! -e "$DOWNLOAD_MARKER"
"""
    result = _bash(
        script,
        env={
            "DOWNLOAD_MARKER": str(marker),
            "TOOL_SPEC_MANIFEST": str(manifest),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "Trivy is already installed and healthy" in result.stdout
    assert not marker.exists()


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_existing_unhealthy_optional_tool_enters_repair_path(tmp_path: Path) -> None:
    executable = tmp_path / "trivy"
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'ModuleNotFoundError: broken runtime'\nexit 0\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="trivy",
        executable="trivy",
        recommended_version="0.73.0",
    )
    marker = tmp_path / "download-attempted"
    script = f"""
source {INSTALLER!s}
TRIVY_VERSION=0.73.0
download_url_to_tmp() {{ printf attempted > "$DOWNLOAD_MARKER"; return 1; }}
if install_trivy_release; then
  exit 31
fi
test -s "$DOWNLOAD_MARKER"
"""
    result = _bash(
        script,
        env={
            "DOWNLOAD_MARKER": str(marker),
            "TOOL_SPEC_MANIFEST": str(manifest),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "Trivy is present but failed its startup probe; attempting repair" in result.stdout
    assert marker.exists()


def test_installer_anchors_project_operations_to_script_directory() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert 'cd "$SCRIPT_DIR"' in installer


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_upgrade_doctor_uses_invoking_user_path_before_shell_reload(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project_python = project / "venv" / "bin" / "python"
    project_python.parent.mkdir(parents=True)
    invoking_home = tmp_path / "invoking-home"
    invoking_user_bin = invoking_home / ".local" / "bin"
    invoking_user_bin.mkdir(parents=True)
    project_python.write_text(
        "#!/bin/sh\n"
        f"case \"${{PATH}}\" in\n"
        f"  \"{invoking_user_bin}:\"*)\n"
        "    printf '%s\\n' '{\"checks\":[{\"name\":\"bin:user-tool\",\"ok\":true,"
        "\"message\":\"verified\",\"details\":{\"tool\":\"user-tool\","
        "\"recommended_version\":\"1.0.0\",\"detected_version\":\"1.0.0\"}}]}'\n"
        "    ;;\n"
        "  *) printf '%s\\n' '{\"not_checks\":true}' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    project_python.chmod(0o755)
    script = f"""
source {INSTALLER!s}
SUPABASH_UPGRADE_TOOLS=1
invoking_home() {{ printf '%s\n' "$TEST_INVOKING_HOME"; }}
cd "$TEST_PROJECT"
verify_versioned_tool_upgrades
"""
    result = _bash(
        script,
        env={
            "PATH": "/usr/bin:/bin",
            "TEST_INVOKING_HOME": str(invoking_home),
            "TEST_PROJECT": str(project),
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Versioned tools match or exceed their ToolSpec baselines" in result.stdout


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_required_tool_health_gate_rejects_outdated_tested_version(tmp_path: Path) -> None:
    executable = tmp_path / "required-test"
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'required-test version v1.2.0'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="required-test",
        executable="required-test",
        doctor_required=True,
        recommended_version="2.0.0",
    )
    result = _bash(
        f"source {INSTALLER!s}; verify_required_tool_health",
        env={
            "TOOL_SPEC_MANIFEST": str(manifest),
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        },
    )

    assert result.returncode != 0
    assert "1.2.0 is older than the tested baseline 2.0.0" in result.stdout


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_required_tool_health_gate_fails_when_registry_binary_is_missing(tmp_path: Path) -> None:
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="required-test",
        executable="supabash-definitely-missing",
        doctor_required=True,
    )
    result = _bash(
        f"source {INSTALLER!s}; verify_required_tool_health",
        env={"TOOL_SPEC_MANIFEST": str(manifest)},
    )

    assert result.returncode != 0
    assert "Required tool verification failed: required-test" in result.stdout


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is an installer prerequisite")
def test_registry_health_probe_rejects_traceback_with_zero_exit(tmp_path: Path) -> None:
    executable = tmp_path / "fake-tool"
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'Traceback (most recent call last):' 'ModuleNotFoundError: broken'\nexit 0\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    manifest = tmp_path / "tools.json"
    _write_installer_manifest(
        manifest,
        tool_id="fake-tool",
        executable="fake-tool",
    )
    result = _bash(
        f"source {INSTALLER!s}; tool_registry_health_check fake-tool {executable!s}",
        env={"TOOL_SPEC_MANIFEST": str(manifest)},
    )

    assert result.returncode != 0


def test_pinned_release_lookup_never_falls_back_to_latest(tmp_path: Path) -> None:
    call_log = tmp_path / "curl-calls.txt"
    script = f"""
source {INSTALLER!s}
curl() {{
  printf '%s\n' "$*" >> "$CALL_LOG"
  return 22
}}
if fetch_github_release_json project/example 9.9.9; then
  exit 10
fi
if grep -q '/releases/latest' "$CALL_LOG"; then
  exit 11
fi
"""
    result = _bash(script, env={"CALL_LOG": str(call_log)})

    assert result.returncode == 0, result.stderr
    calls = call_log.read_text(encoding="utf-8")
    assert "/releases/tags/9.9.9" in calls
    assert "/releases/tags/v9.9.9" in calls


def test_release_checksum_verification_rejects_tampering(tmp_path: Path) -> None:
    archive = tmp_path / "tool_1.0_linux_amd64.zip"
    archive.write_bytes(b"verified archive")
    checksum = tmp_path / "tool_1.0_checksums.txt"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    release_json = (
        '{"assets":[{"name":"tool_1.0_checksums.txt",'
        '"browser_download_url":"checksum-url"}]}'
    )
    script = f"""
source {INSTALLER!s}
download_url_to_tmp() {{ cp "$CHECKSUM_SOURCE" "$2/$3"; }}
verify_release_asset_checksum "$RELEASE_JSON" "$ASSET_NAME" "$ASSET_DIR"
printf tampered >> "$ASSET_DIR/$ASSET_NAME"
if verify_release_asset_checksum "$RELEASE_JSON" "$ASSET_NAME" "$ASSET_DIR"; then
  exit 12
fi
"""
    result = _bash(
        script,
        env={
            "ASSET_DIR": str(tmp_path),
            "ASSET_NAME": archive.name,
            "CHECKSUM_SOURCE": str(checksum),
            "RELEASE_JSON": release_json,
        },
    )

    assert result.returncode == 0, result.stderr
