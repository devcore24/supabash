"""Typed access to Supabash's versioned tool specification manifest.

The manifest is deliberately plain JSON so non-Python consumers (notably the
installer) can read the same tool metadata without importing Supabash.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from itertools import zip_longest
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple


TOOL_SPEC_SCHEMA_VERSION = 1
TOOL_SPEC_RESOURCE = "data/tool_specs.v1.json"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_INSTALL_METHODS = {
    "github_release",
    "go",
    "internal",
    "mixed",
    "pipx",
    "ruby_gem",
    "system_package",
}
_VERSION_TOKEN_RE = re.compile(r"[vV]?(\d+(?:\.\d+)+)(?:[A-Za-z0-9._+#-]*)")
_SAFE_EXECUTABLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SAFE_FIXED_EXECUTABLE_RE = re.compile(
    r"^/(?:usr/local/bin|usr/bin)/[A-Za-z0-9][A-Za-z0-9._+-]*$"
)
FATAL_HEALTH_MARKERS = (
    "traceback (most recent call last)",
    "modulenotfounderror:",
    "importerror:",
    "error while loading shared libraries",
    "cannot open shared object file",
    "command not found",
)


class ToolRegistryError(ValueError):
    """Raised when a tool registry manifest is malformed or unsupported."""


@dataclass(frozen=True)
class HealthProbeSpec:
    """A safe, local command used to prove that an executable can start."""

    argv: Tuple[str, ...]
    success_exit_codes: Tuple[int, ...] = (0,)
    timeout_seconds: int = 8

    def render(self, executable: str) -> Tuple[str, ...]:
        return tuple(executable if token == "{executable}" else token for token in self.argv)


@dataclass(frozen=True)
class ExecutableHealthResult:
    """Result of a bounded, local ToolSpec startup probe."""

    path: str
    command: Tuple[str, ...]
    ok: bool
    return_code: Optional[int]
    output: str = ""
    fatal_marker: Optional[str] = None
    error: Optional[str] = None
    timed_out: bool = False


@dataclass(frozen=True)
class ExecutableCandidateEvaluation:
    """Health and version assessment for one unique resolved executable path."""

    candidates: Tuple[str, ...]
    path: str
    health: ExecutableHealthResult
    detected_version: Optional[str]
    version_status: Optional[str]
    rank: int


@dataclass(frozen=True)
class ExecutableResolution:
    """Ordered candidate discovery plus the shared best-path decision."""

    candidate_paths: Tuple[Tuple[str, Optional[str]], ...]
    evaluations: Tuple[ExecutableCandidateEvaluation, ...]
    selected: Optional[ExecutableCandidateEvaluation]

    @property
    def healthy_path(self) -> Optional[str]:
        if self.selected is None or not self.selected.health.ok:
            return None
        return self.selected.path


@dataclass(frozen=True)
class ExecutableSpec:
    """One executable dependency, including ordered compatible binary names."""

    id: str
    candidates: Tuple[str, ...]
    required: bool
    doctor_check: bool
    doctor_name: Optional[str]
    doctor_required: Optional[bool]
    version_commands: Tuple[Tuple[str, ...], ...]
    health_probe: Optional[HealthProbeSpec]
    python_distribution: Optional[str]

    @property
    def preferred_candidate(self) -> str:
        return self.candidates[0]

    def render_version_commands(self, executable: Optional[str] = None) -> Tuple[Tuple[str, ...], ...]:
        selected = str(executable or self.preferred_candidate)
        return tuple(
            tuple(selected if token == "{executable}" else token for token in argv)
            for argv in self.version_commands
        )


@dataclass(frozen=True)
class ToolSpec:
    """Static metadata for one Supabash wrapper."""

    id: str
    wrapper: str
    config_key: str
    aliases: Tuple[str, ...]
    description: str
    target_kinds: Tuple[str, ...]
    default_enabled: bool
    doctor_required: bool
    recommended_version: Optional[str]
    install_method: str
    privileges: Tuple[str, ...]
    datasets: Tuple[str, ...]
    credentials: Tuple[str, ...]
    executables: Tuple[ExecutableSpec, ...]

    @property
    def names(self) -> Tuple[str, ...]:
        return (self.id, *self.aliases)

    @property
    def primary_executable(self) -> Optional[ExecutableSpec]:
        return self.executables[0] if self.executables else None

    def executable(self, executable_id: Optional[str] = None) -> Optional[ExecutableSpec]:
        if executable_id is None:
            return self.primary_executable
        token = str(executable_id or "").strip().lower()
        return next((item for item in self.executables if item.id == token), None)


@dataclass(frozen=True)
class ToolRegistry:
    """Validated immutable registry with canonical and alias lookup."""

    schema_version: int
    registry_version: str
    tools: Tuple[ToolSpec, ...]
    _lookup: Mapping[str, ToolSpec] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        lookup: Dict[str, ToolSpec] = {}
        for spec in self.tools:
            for name in spec.names:
                token = _normalize_name(name)
                if token in lookup:
                    raise ToolRegistryError(
                        f"duplicate tool id/alias {name!r} shared by "
                        f"{lookup[token].id!r} and {spec.id!r}"
                    )
                lookup[token] = spec
        object.__setattr__(self, "_lookup", MappingProxyType(lookup))

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._lookup.get(_normalize_name(name))

    def require(self, name: str) -> ToolSpec:
        spec = self.get(name)
        if spec is None:
            raise KeyError(f"unknown Supabash tool: {name}")
        return spec

    def version_commands(
        self,
        name: str,
        *,
        executable: Optional[str] = None,
        executable_id: Optional[str] = None,
    ) -> Tuple[Tuple[str, ...], ...]:
        spec = self.get(name)
        if spec is None:
            return ()
        executable_spec = spec.executable(executable_id)
        if executable_spec is None:
            return ()
        return executable_spec.render_version_commands(executable)


def _normalize_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _error(source: str, path: str, message: str) -> ToolRegistryError:
    return ToolRegistryError(f"{source}: {path}: {message}")


def _mapping(value: Any, *, source: str, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _error(source, path, "must be an object")
    return value


def _reject_unknown(
    value: Mapping[str, Any],
    allowed: Iterable[str],
    *,
    source: str,
    path: str,
) -> None:
    unknown = sorted(set(value).difference(allowed))
    if unknown:
        raise _error(source, path, f"unknown field(s): {', '.join(unknown)}")


def _required_string(value: Mapping[str, Any], key: str, *, source: str, path: str) -> str:
    raw = value.get(key)
    if not isinstance(raw, str) or not raw.strip():
        raise _error(source, f"{path}.{key}", "must be a non-empty string")
    return raw.strip()


def _optional_string(value: Any, *, source: str, path: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise _error(source, path, "must be null or a non-empty string")
    return value.strip()


def _boolean(value: Mapping[str, Any], key: str, *, source: str, path: str) -> bool:
    raw = value.get(key)
    if not isinstance(raw, bool):
        raise _error(source, f"{path}.{key}", "must be a boolean")
    return raw


def _string_tuple(
    value: Any,
    *,
    source: str,
    path: str,
    allow_empty: bool = True,
) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise _error(source, path, "must be an array of strings")
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise _error(source, f"{path}[{index}]", "must be a non-empty string")
        token = item.strip()
        if token in result:
            raise _error(source, path, f"contains duplicate value {token!r}")
        result.append(token)
    if not allow_empty and not result:
        raise _error(source, path, "must not be empty")
    return tuple(result)


def _command(value: Any, *, source: str, path: str) -> Tuple[str, ...]:
    argv = _string_tuple(value, source=source, path=path, allow_empty=False)
    if argv[0] != "{executable}":
        raise _error(source, path, "must start with the {executable} placeholder")
    if argv.count("{executable}") != 1:
        raise _error(source, path, "must contain {executable} exactly once")
    return argv


def _parse_health_probe(value: Any, *, source: str, path: str) -> Optional[HealthProbeSpec]:
    if value is None:
        return None
    obj = _mapping(value, source=source, path=path)
    _reject_unknown(
        obj,
        {"argv", "success_exit_codes", "timeout_seconds"},
        source=source,
        path=path,
    )
    argv = _command(obj.get("argv"), source=source, path=f"{path}.argv")
    raw_codes = obj.get("success_exit_codes", [0])
    if not isinstance(raw_codes, list) or not raw_codes:
        raise _error(source, f"{path}.success_exit_codes", "must be a non-empty integer array")
    codes = []
    for index, item in enumerate(raw_codes):
        if not isinstance(item, int) or isinstance(item, bool) or item < 0 or item > 255:
            raise _error(
                source,
                f"{path}.success_exit_codes[{index}]",
                "must be an integer between 0 and 255",
            )
        if item in codes:
            raise _error(source, f"{path}.success_exit_codes", f"contains duplicate {item}")
        codes.append(item)
    timeout = obj.get("timeout_seconds", 8)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 30:
        raise _error(source, f"{path}.timeout_seconds", "must be an integer from 1 to 30")
    return HealthProbeSpec(argv=argv, success_exit_codes=tuple(codes), timeout_seconds=timeout)


def _parse_executable(value: Any, *, source: str, path: str) -> ExecutableSpec:
    obj = _mapping(value, source=source, path=path)
    _reject_unknown(
        obj,
        {
            "id",
            "candidates",
            "required",
            "doctor_check",
            "doctor_name",
            "doctor_required",
            "version_commands",
            "health_probe",
            "python_distribution",
        },
        source=source,
        path=path,
    )
    executable_id = _required_string(obj, "id", source=source, path=path).lower()
    if not _ID_RE.fullmatch(executable_id):
        raise _error(source, f"{path}.id", "must contain only lowercase letters, digits, '_' or '-'")
    candidates = _string_tuple(
        obj.get("candidates"), source=source, path=f"{path}.candidates", allow_empty=False
    )
    for index, candidate in enumerate(candidates):
        if not (
            _SAFE_EXECUTABLE_NAME_RE.fullmatch(candidate)
            or _SAFE_FIXED_EXECUTABLE_RE.fullmatch(candidate)
        ):
            raise _error(
                source,
                f"{path}.candidates[{index}]",
                "must be a safe executable name or a fixed /usr[/local]/bin path",
            )
    required = _boolean(obj, "required", source=source, path=path)
    doctor_check = _boolean(obj, "doctor_check", source=source, path=path)
    doctor_name = _optional_string(obj.get("doctor_name"), source=source, path=f"{path}.doctor_name")
    doctor_required_raw = obj.get("doctor_required")
    if doctor_required_raw is not None and not isinstance(doctor_required_raw, bool):
        raise _error(source, f"{path}.doctor_required", "must be null or a boolean")
    raw_commands = obj.get("version_commands")
    if not isinstance(raw_commands, list):
        raise _error(source, f"{path}.version_commands", "must be an array of argv arrays")
    version_commands = tuple(
        _command(item, source=source, path=f"{path}.version_commands[{index}]")
        for index, item in enumerate(raw_commands)
    )
    health_probe = _parse_health_probe(
        obj.get("health_probe"), source=source, path=f"{path}.health_probe"
    )
    python_distribution = _optional_string(
        obj.get("python_distribution"),
        source=source,
        path=f"{path}.python_distribution",
    )
    return ExecutableSpec(
        id=executable_id,
        candidates=candidates,
        required=required,
        doctor_check=doctor_check,
        doctor_name=doctor_name,
        doctor_required=doctor_required_raw,
        version_commands=version_commands,
        health_probe=health_probe,
        python_distribution=python_distribution,
    )


def _parse_tool(value: Any, *, source: str, path: str) -> ToolSpec:
    obj = _mapping(value, source=source, path=path)
    _reject_unknown(
        obj,
        {
            "id",
            "wrapper",
            "config_key",
            "aliases",
            "description",
            "target_kinds",
            "default_enabled",
            "doctor_required",
            "recommended_version",
            "install_method",
            "privileges",
            "datasets",
            "credentials",
            "executables",
        },
        source=source,
        path=path,
    )
    tool_id = _required_string(obj, "id", source=source, path=path).lower()
    if not _ID_RE.fullmatch(tool_id):
        raise _error(source, f"{path}.id", "must contain only lowercase letters, digits, '_' or '-'")
    config_key = _required_string(obj, "config_key", source=source, path=path).lower()
    if not _ID_RE.fullmatch(config_key):
        raise _error(source, f"{path}.config_key", "must be a valid lowercase tool key")
    wrapper = _required_string(obj, "wrapper", source=source, path=path)
    if ":" not in wrapper or wrapper.startswith(":") or wrapper.endswith(":"):
        raise _error(source, f"{path}.wrapper", "must use module.path:ClassName syntax")
    aliases = _string_tuple(obj.get("aliases"), source=source, path=f"{path}.aliases")
    for index, alias in enumerate(aliases):
        if not _ID_RE.fullmatch(alias.lower()):
            raise _error(source, f"{path}.aliases[{index}]", "must be a valid tool alias")
        if alias.lower() == tool_id:
            raise _error(source, f"{path}.aliases[{index}]", "must not repeat the canonical id")
    description = _required_string(obj, "description", source=source, path=path)
    target_kinds = _string_tuple(
        obj.get("target_kinds"), source=source, path=f"{path}.target_kinds", allow_empty=False
    )
    default_enabled = _boolean(obj, "default_enabled", source=source, path=path)
    doctor_required = _boolean(obj, "doctor_required", source=source, path=path)
    recommended_version = _optional_string(
        obj.get("recommended_version"), source=source, path=f"{path}.recommended_version"
    )
    install_method = _required_string(obj, "install_method", source=source, path=path)
    if install_method not in _INSTALL_METHODS:
        raise _error(
            source,
            f"{path}.install_method",
            f"must be one of {', '.join(sorted(_INSTALL_METHODS))}",
        )
    privileges = _string_tuple(obj.get("privileges"), source=source, path=f"{path}.privileges")
    datasets = _string_tuple(obj.get("datasets"), source=source, path=f"{path}.datasets")
    credentials = _string_tuple(obj.get("credentials"), source=source, path=f"{path}.credentials")
    raw_executables = obj.get("executables")
    if not isinstance(raw_executables, list):
        raise _error(source, f"{path}.executables", "must be an array")
    executables = tuple(
        _parse_executable(item, source=source, path=f"{path}.executables[{index}]")
        for index, item in enumerate(raw_executables)
    )
    executable_ids = [item.id for item in executables]
    if len(executable_ids) != len(set(executable_ids)):
        raise _error(source, f"{path}.executables", "contains duplicate executable ids")
    if doctor_required and not any(item.doctor_check for item in executables):
        raise _error(source, path, "doctor_required tools need a doctor-checked executable")
    return ToolSpec(
        id=tool_id,
        wrapper=wrapper,
        config_key=config_key,
        aliases=tuple(alias.lower() for alias in aliases),
        description=description,
        target_kinds=target_kinds,
        default_enabled=default_enabled,
        doctor_required=doctor_required,
        recommended_version=recommended_version,
        install_method=install_method,
        privileges=privileges,
        datasets=datasets,
        credentials=credentials,
        executables=executables,
    )


def parse_tool_registry(payload: Any, *, source: str = "<memory>") -> ToolRegistry:
    """Validate a decoded JSON payload and return an immutable registry."""

    obj = _mapping(payload, source=source, path="$")
    _reject_unknown(obj, {"schema_version", "registry_version", "tools"}, source=source, path="$")
    schema_version = obj.get("schema_version")
    if schema_version != TOOL_SPEC_SCHEMA_VERSION:
        raise _error(
            source,
            "$.schema_version",
            f"unsupported value {schema_version!r}; expected {TOOL_SPEC_SCHEMA_VERSION}",
        )
    registry_version = _required_string(obj, "registry_version", source=source, path="$")
    raw_tools = obj.get("tools")
    if not isinstance(raw_tools, list) or not raw_tools:
        raise _error(source, "$.tools", "must be a non-empty array")
    tools = tuple(
        _parse_tool(item, source=source, path=f"$.tools[{index}]")
        for index, item in enumerate(raw_tools)
    )
    tool_ids = [item.id for item in tools]
    if len(tool_ids) != len(set(tool_ids)):
        raise _error(source, "$.tools", "contains duplicate canonical tool ids")
    config_keys = [item.config_key for item in tools]
    if len(config_keys) != len(set(config_keys)):
        raise _error(source, "$.tools", "contains duplicate config keys")
    return ToolRegistry(
        schema_version=schema_version,
        registry_version=registry_version,
        tools=tools,
    )


def load_tool_registry(path: Optional[Path] = None) -> ToolRegistry:
    """Load a registry from ``path`` or from Supabash package data."""

    if path is None:
        return _load_builtin_tool_registry()
    source_path = Path(path)
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolRegistryError(f"{source_path}: unable to load tool registry: {exc}") from exc
    return parse_tool_registry(payload, source=str(source_path))


@lru_cache(maxsize=1)
def _load_builtin_tool_registry() -> ToolRegistry:
    resource = resources.files("supabash").joinpath(TOOL_SPEC_RESOURCE)
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolRegistryError(f"{TOOL_SPEC_RESOURCE}: unable to load tool registry: {exc}") from exc
    return parse_tool_registry(payload, source=TOOL_SPEC_RESOURCE)


def version_commands_for_tool(
    tool: str,
    *,
    executable: Optional[str] = None,
    executable_id: Optional[str] = None,
) -> Tuple[Tuple[str, ...], ...]:
    """Return rendered version commands for a canonical tool id or alias."""

    return load_tool_registry().version_commands(
        tool,
        executable=executable,
        executable_id=executable_id,
    )


def iter_doctor_executables(
    registry: Optional[ToolRegistry] = None,
) -> Iterable[Tuple[ToolSpec, ExecutableSpec]]:
    """Yield executable groups that should appear in ``supabash doctor``."""

    selected = registry or load_tool_registry()
    for tool in selected.tools:
        for executable in tool.executables:
            if executable.doctor_check:
                yield tool, executable


def resolve_executable_candidates(
    executable: ExecutableSpec,
    *,
    which: Optional[Callable[[str], Optional[str]]] = None,
) -> Tuple[Tuple[str, Optional[str]], ...]:
    """Resolve ToolSpec candidates in declared order.

    Fixed system paths can precede ambiguous PATH names in the manifest. This is
    important for tools such as ProjectDiscovery httpx, whose executable name is
    also used by an unrelated Python package.
    """

    resolver = which or shutil.which
    resolved = []
    for candidate in executable.candidates:
        try:
            path = resolver(candidate)
        except (OSError, TypeError, ValueError):
            path = None
        normalized = str(path).strip() if path else None
        # An empty or relative PATH entry can otherwise select an executable
        # from the caller's current directory. Tool execution is always pinned
        # to an absolute path after discovery.
        if normalized and not os.path.isabs(normalized):
            normalized = None
        resolved.append((candidate, normalized or None))
    return tuple(resolved)


def resolve_executable(
    executable: ExecutableSpec,
    *,
    which: Optional[Callable[[str], Optional[str]]] = None,
) -> Optional[str]:
    """Return the first available executable using ToolSpec ordering."""

    return next(
        (
            path
            for _candidate, path in resolve_executable_candidates(executable, which=which)
            if path
        ),
        None,
    )


def probe_executable_health(
    executable: ExecutableSpec,
    path: str,
    *,
    run: Optional[Callable[..., Any]] = None,
) -> ExecutableHealthResult:
    """Run one bounded ToolSpec health probe without invoking a shell."""

    selected = str(path or "").strip()
    probe = executable.health_probe
    if not selected or not os.path.isabs(selected):
        return ExecutableHealthResult(
            path=selected,
            command=(),
            ok=False,
            return_code=None,
            error="resolved executable path is not absolute",
        )
    if probe is None:
        return ExecutableHealthResult(
            path=selected,
            command=(),
            ok=False,
            return_code=None,
            error="health probe is not configured",
        )

    command = probe.render(selected)
    runner = run or subprocess.run
    try:
        completed = runner(
            list(command),
            capture_output=True,
            text=True,
            timeout=probe.timeout_seconds,
            check=False,
        )
        return_code = int(completed.returncode)
        output = "\n".join(
            part
            for part in (
                str(getattr(completed, "stdout", "") or ""),
                str(getattr(completed, "stderr", "") or ""),
            )
            if part.strip()
        ).strip()
        fatal_marker = next(
            (marker for marker in FATAL_HEALTH_MARKERS if marker in output.lower()),
            None,
        )
        return ExecutableHealthResult(
            path=selected,
            command=command,
            ok=return_code in probe.success_exit_codes and fatal_marker is None,
            return_code=return_code,
            output=output[:4096],
            fatal_marker=fatal_marker,
        )
    except subprocess.TimeoutExpired:
        return ExecutableHealthResult(
            path=selected,
            command=command,
            ok=False,
            return_code=None,
            error=f"health probe timed out after {probe.timeout_seconds} seconds",
            timed_out=True,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        return ExecutableHealthResult(
            path=selected,
            command=command,
            ok=False,
            return_code=None,
            error=f"health probe failed: {exc}",
        )


def resolve_best_executable(
    executable: ExecutableSpec,
    *,
    recommended_version: Optional[str] = None,
    tool_names: Sequence[str] = (),
    which: Optional[Callable[[str], Optional[str]]] = None,
    run: Optional[Callable[..., Any]] = None,
    distribution_version: Optional[Callable[..., Optional[str]]] = None,
) -> ExecutableResolution:
    """Probe and rank every unique path using one runtime/Doctor policy.

    Compatible versions rank first, followed by healthy candidates whose
    version cannot be established, then healthy outdated candidates. Broken or
    wrong executables never become runtime selections.
    """

    candidate_paths = resolve_executable_candidates(executable, which=which)
    ordered_paths = []
    candidates_by_path: Dict[str, list[str]] = {}
    for candidate, path in candidate_paths:
        if not path:
            continue
        if path not in candidates_by_path:
            candidates_by_path[path] = []
            ordered_paths.append(path)
        candidates_by_path[path].append(candidate)

    evaluations = []
    version_resolver = distribution_version or python_distribution_version
    for path in ordered_paths:
        health = probe_executable_health(executable, path, run=run)
        detected_version = None
        if health.ok and executable.python_distribution:
            try:
                detected_version = version_resolver(
                    path,
                    executable.python_distribution,
                    timeout_seconds=min(
                        executable.health_probe.timeout_seconds
                        if executable.health_probe is not None
                        else 6,
                        6,
                    ),
                )
            except (OSError, TypeError, ValueError):
                detected_version = None
        elif health.ok and executable.version_commands:
            detected_version = extract_version_from_output(
                health.output,
                tool_names=(*tool_names, *executable.candidates),
            )

        version_status = None
        rank = 0
        if health.ok and recommended_version:
            comparison = (
                compare_numeric_versions(detected_version, recommended_version)
                if detected_version
                else None
            )
            if comparison is None:
                version_status = "unavailable"
                rank = 2
            elif comparison < 0:
                version_status = "outdated"
                rank = 1
            elif comparison > 0:
                version_status = "newer_than_recommended"
                rank = 3
            else:
                version_status = "recommended"
                rank = 3
        elif health.ok:
            rank = 3

        evaluations.append(
            ExecutableCandidateEvaluation(
                candidates=tuple(candidates_by_path[path]),
                path=path,
                health=health,
                detected_version=detected_version,
                version_status=version_status,
                rank=rank,
            )
        )

    selected = max(evaluations, key=lambda item: item.rank) if evaluations else None
    return ExecutableResolution(
        candidate_paths=candidate_paths,
        evaluations=tuple(evaluations),
        selected=selected,
    )


def resolve_healthy_executable(
    executable: ExecutableSpec,
    *,
    recommended_version: Optional[str] = None,
    tool_names: Sequence[str] = (),
    which: Optional[Callable[[str], Optional[str]]] = None,
    run: Optional[Callable[..., Any]] = None,
    distribution_version: Optional[Callable[..., Optional[str]]] = None,
) -> Optional[str]:
    """Return the highest-ranked healthy ToolSpec candidate."""

    resolution = resolve_best_executable(
        executable,
        recommended_version=recommended_version,
        tool_names=tool_names,
        which=which,
        run=run,
        distribution_version=distribution_version,
    )
    return resolution.healthy_path


def resolve_tool_executable(
    tool: str,
    *,
    executable_id: Optional[str] = None,
    registry: Optional[ToolRegistry] = None,
    which: Optional[Callable[[str], Optional[str]]] = None,
    require_healthy: bool = False,
    run: Optional[Callable[..., Any]] = None,
) -> Optional[str]:
    """Resolve a canonical tool or alias through the shared ToolSpec registry."""

    selected = registry or load_tool_registry()
    tool_spec = selected.get(tool)
    if tool_spec is None:
        return None
    executable = tool_spec.executable(executable_id)
    if executable is None:
        return None
    if require_healthy:
        return resolve_healthy_executable(
            executable,
            recommended_version=tool_spec.recommended_version,
            tool_names=tool_spec.names,
            which=which,
            run=run,
        )
    return resolve_executable(executable, which=which)


def extract_version_from_output(text: Any, *, tool_names: Sequence[str] = ()) -> Optional[str]:
    """Extract a best-effort semantic version while avoiding common license noise."""

    output = str(text or "")
    if not output.strip():
        return None
    normalized_names = tuple(
        str(name or "").strip().lower().replace("_", "-")
        for name in tool_names
        if str(name or "").strip()
    )
    if "hydra" in normalized_names:
        match = re.search(r"(?i)\bhydra\s+v?(\d+(?:\.\d+)+[A-Za-z0-9._+#-]*)", output)
        if match:
            return match.group(1)

    best: Optional[Tuple[int, str]] = None
    for raw_line in output.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        low = line.lower().replace("_", "-")
        if any(marker in low for marker in ("agpl", "gpl license", "license version")):
            continue
        matches = list(_VERSION_TOKEN_RE.finditer(line))
        if not matches:
            continue
        score = 10
        if "version" in low:
            score = 100
        elif normalized_names and any(name in low for name in normalized_names):
            score = 90
        elif _VERSION_TOKEN_RE.fullmatch(line):
            score = 80
        elif len(line) <= 64:
            score = 40
        value = matches[0].group(0)
        if best is None or score > best[0]:
            best = (score, value)
    return best[1] if best else None


def compare_numeric_versions(left: str, right: str) -> Optional[int]:
    """Compare numeric release components; return None when either value is unparseable."""

    def components(value: str) -> Optional[Tuple[int, ...]]:
        match = re.match(r"^[vV]?(\d+(?:\.\d+)+)", str(value or "").strip())
        if not match:
            return None
        return tuple(int(part) for part in match.group(1).split("."))

    left_parts = components(left)
    right_parts = components(right)
    if left_parts is None or right_parts is None:
        return None
    for left_part, right_part in zip_longest(left_parts, right_parts, fillvalue=0):
        if left_part < right_part:
            return -1
        if left_part > right_part:
            return 1
    return 0


def python_distribution_version(
    executable: str,
    distribution: str,
    *,
    timeout_seconds: int = 6,
) -> Optional[str]:
    """Query package metadata through a Python entrypoint's isolated interpreter."""

    try:
        entrypoint = Path(executable).expanduser().resolve(strict=True)
        with entrypoint.open("r", encoding="utf-8", errors="ignore") as stream:
            first_line = stream.readline(4097).rstrip("\r\n")
        if len(first_line) > 4096:
            return None
        if not first_line.startswith("#!"):
            return None
        interpreter = Path(first_line[2:].strip())
        if not interpreter.is_absolute() or not interpreter.is_file() or not os.access(interpreter, os.X_OK):
            return None
        completed = subprocess.run(
            [
                str(interpreter),
                "-c",
                "import importlib.metadata,sys; print(importlib.metadata.version(sys.argv[1]))",
                str(distribution),
            ],
            capture_output=True,
            text=True,
            timeout=max(1, min(int(timeout_seconds), 30)),
            check=False,
            env={
                key: value
                for key, value in os.environ.items()
                if key in {"HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE"}
            },
        )
        value = str(completed.stdout or "").strip()
        if completed.returncode != 0 or len(value) > 128:
            return None
        if not re.match(r"^[vV]?\d+(?:\.\d+)+[A-Za-z0-9._+#-]*$", value):
            return None
        return value
    except (OSError, IndexError, subprocess.SubprocessError, ValueError):
        return None
