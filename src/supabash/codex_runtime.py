"""Safe, non-interactive Codex CLI runtime for Supabash.

The runtime deliberately keeps Codex behind a small machine-oriented contract:
prompts are sent over stdin, responses are constrained by JSON Schema, and the
JSONL event stream is captured independently from stderr.  It does not use a
shell and it never places prompt content on the process command line.
"""

from __future__ import annotations

import codecs
import fcntl
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Tuple, Union

from supabash.redaction import redact_sensitive_data, redact_sensitive_text


PathValue = Union[str, os.PathLike[str]]

AMBIENT_CODEX_CONTEXT_VARS = (
    "CODEX_THREAD_ID",
    "CODEX_SQLITE_HOME",
    "CODEX_PERMISSION_PROFILE",
    "CODEX_INTERNAL_ORIGINATOR_OVERRIDE",
)
FORCED_CONFIG_OVERRIDES = (
    'web_search="disabled"',
    "include_environment_context=false",
    "include_permissions_instructions=false",
    "include_apps_instructions=false",
    "include_collaboration_mode_instructions=false",
    "skills.include_instructions=false",
    "skills.bundled.enabled=false",
)
MAX_CODEX_INPUT_CHARS = 1_000_000
MAX_CODEX_EVENTS = 1_000
MAX_CODEX_EVENT_CHARS = 32_768
MAX_CODEX_STDERR_CHARS = 262_144
KNOWN_CODEX_EVENT_TYPES = frozenset(
    {
        "thread.started",
        "turn.started",
        "turn.completed",
        "turn.failed",
        "item.started",
        "item.updated",
        "item.completed",
        "error",
    }
)
CODEX_ITEM_EVENT_TYPES = frozenset({"item.started", "item.updated", "item.completed"})


def ambient_codex_context_keys(
    environment: Optional[Mapping[str, str]] = None,
) -> Tuple[str, ...]:
    """Return parent Codex/App context markers that make nested turns unsafe."""
    source = environment if environment is not None else os.environ
    return tuple(key for key in AMBIENT_CODEX_CONTEXT_VARS if str(source.get(key) or "").strip())


class CodexRuntimeError(RuntimeError):
    """Raised when Codex cannot safely be started."""


@dataclass(frozen=True)
class CodexRuntimeConfig:
    """Configuration for a local ``codex exec`` process."""

    command: str = "codex"
    cwd: Optional[PathValue] = None
    timeout_seconds: float = 900.0
    preflight_timeout_seconds: float = 10.0
    sandbox: str = "read-only"
    require_chatgpt: bool = True
    ignore_user_config: bool = True
    persistent_thread: bool = False
    model: Optional[str] = None
    codex_home: Optional[PathValue] = None
    max_events: int = 500
    max_event_chars: int = 16_384
    max_input_chars: int = 24_000
    max_stderr_chars: int = 65_536
    poll_interval_seconds: float = 0.05
    terminate_grace_seconds: float = 1.0
    disable_web_search: bool = True
    disabled_features: Tuple[str, ...] = (
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
    )


@dataclass(frozen=True)
class CodexPreflight:
    """Result of inspecting the installed Codex CLI and its login mode."""

    command: str
    installed: bool
    version: Optional[str]
    authenticated: bool
    auth_mode: Optional[str]
    is_chatgpt: bool
    ready: bool
    error: Optional[str] = None
    capabilities_ok: bool = True
    missing_capabilities: Tuple[str, ...] = ()
    global_instructions_ok: bool = True
    global_instruction_files: Tuple[str, ...] = ()


@dataclass(frozen=True)
class CodexRunResult:
    """Bounded, redacted result from one Codex turn."""

    success: bool
    return_code: int
    thread_id: Optional[str]
    structured_output: Any
    final_text: str
    events: Tuple[Dict[str, Any], ...]
    usage: Dict[str, int]
    stderr: str
    error: Optional[str]
    timed_out: bool
    canceled: bool
    duration_seconds: float
    argv: Tuple[str, ...]
    malformed_event_count: int
    stdout_truncated: bool
    stderr_truncated: bool
    policy_event_types: Tuple[str, ...] = ()
    protocol_event_count: int = 0
    lifecycle_complete: bool = True
    stream_incomplete: bool = False


class _BoundedTextCapture:
    """Consume a stream without blocking while retaining bounded head/tail data."""

    def __init__(self, limit: int) -> None:
        self.limit = max(2, int(limit))
        self.head_limit = self.limit // 2
        self.tail_limit = self.limit - self.head_limit
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    def feed(self, data: bytes) -> None:
        if not data:
            return
        self.total += len(data)
        remaining = data
        if len(self.head) < self.head_limit:
            count = min(self.head_limit - len(self.head), len(remaining))
            self.head.extend(remaining[:count])
            remaining = remaining[count:]
        if remaining:
            self.tail.extend(remaining)
            if len(self.tail) > self.tail_limit:
                del self.tail[: len(self.tail) - self.tail_limit]

    @property
    def truncated(self) -> bool:
        return self.total > self.limit

    def text(self) -> str:
        if self.total <= self.limit:
            raw = bytes(self.head + self.tail)
            return raw.decode("utf-8", errors="replace")
        head = bytes(self.head).decode("utf-8", errors="replace")
        tail = bytes(self.tail).decode("utf-8", errors="replace")
        return f"{head}\n<output truncated>\n{tail}"


class _JsonlCapture:
    """Incrementally parse and bound a forward-compatible JSONL event stream."""

    def __init__(self, max_events: int, max_event_chars: int) -> None:
        self.max_events = max(1, int(max_events))
        self.max_event_chars = max(256, int(max_event_chars))
        self._head_limit = max(1, self.max_events // 2)
        self._tail_limit = max(0, self.max_events - self._head_limit)
        self._head: list[Dict[str, Any]] = []
        self._tail: deque[Dict[str, Any]] = deque(maxlen=self._tail_limit or 1)
        self._event_count = 0
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._buffer = ""
        self._discard_line = False
        self.thread_id: Optional[str] = None
        self.usage: Dict[str, int] = {}
        self.last_agent_text = ""
        self.error_message = ""
        self.policy_event_types: set[str] = set()
        self.object_event_count = 0
        self.thread_started_seen = False
        self.turn_completed_seen = False
        self.failure_event_seen = False
        self.malformed_count = 0
        self.truncated = False

    def feed(self, data: bytes) -> None:
        try:
            text = self._decoder.decode(data)
        except UnicodeDecodeError:
            self._store_malformed("", reason="invalid UTF-8 in JSONL stream")
            self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
            self._buffer = ""
            text = data.decode("utf-8", errors="replace")
        if not text:
            return
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if self._discard_line:
                self._discard_line = False
                continue
            self._consume_line(line.rstrip("\r"))
        if len(self._buffer) > self.max_event_chars:
            preview = self._buffer[: self.max_event_chars]
            self._store_malformed(preview, reason="event exceeded size limit")
            self._buffer = ""
            self._discard_line = True
            self.truncated = True

    def finish(self) -> None:
        try:
            self._buffer += self._decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            self._store_malformed("", reason="incomplete UTF-8 in JSONL stream")
        if self._buffer and not self._discard_line:
            self._consume_line(self._buffer.rstrip("\r"))
        self._buffer = ""

    def _extract_metadata(self, event: Mapping[str, Any]) -> None:
        self.object_event_count += 1
        event_type = str(event.get("type") or "").strip().lower()
        if event_type not in KNOWN_CODEX_EVENT_TYPES:
            self._store_malformed(
                event_type,
                reason="unknown or missing Codex event type",
            )

        thread_id = event.get("thread_id")
        if isinstance(thread_id, str) and thread_id.strip():
            self.thread_id = thread_id.strip()[:256]
        elif event_type == "thread.started":
            self._store_malformed("", reason="thread.started is missing a valid thread_id")

        usage = event.get("usage")
        if isinstance(usage, Mapping):
            for key, value in usage.items():
                if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool):
                    self.usage[key[:128]] = value

        item = event.get("item")
        if event_type in CODEX_ITEM_EVENT_TYPES and not isinstance(item, Mapping):
            self._store_malformed("", reason=f"{event_type} is missing an object item")
        elif event_type not in CODEX_ITEM_EVENT_TYPES and "item" in event:
            self._store_malformed("", reason=f"{event_type or 'event'} contains an unexpected item")
        if isinstance(item, Mapping) and item.get("type") == "agent_message":
            text = item.get("text")
            if isinstance(text, str):
                self.last_agent_text = text

        for candidate in (event.get("type"), item.get("type") if isinstance(item, Mapping) else None):
            normalized = str(candidate or "").strip().lower().replace("-", "_")
            if normalized in {"command_execution", "file_change", "mcp_tool_call", "web_search"}:
                self.policy_event_types.add(normalized)

        if event_type == "thread.started":
            self.thread_started_seen = True
        elif event_type == "turn.completed":
            self.turn_completed_seen = True
        elif event_type in {"turn.failed", "error"}:
            self.failure_event_seen = True

        if isinstance(item, Mapping):
            item_type = str(item.get("type") or "").strip().lower().replace("-", "_")
            known_item_types = {
                "agent_message",
                "reasoning",
                "plan",
                "todo_list",
                "command_execution",
                "file_change",
                "mcp_tool_call",
                "web_search",
            }
            if not item_type or item_type not in known_item_types:
                self._store_malformed(
                    item_type,
                    reason="unknown or missing Codex item type",
                )
        if event_type in {"error", "turn.failed"}:
            message = event.get("message")
            error = event.get("error")
            if not isinstance(message, str) and isinstance(error, Mapping):
                message = error.get("message")
            if isinstance(message, str) and message.strip():
                self.error_message = redact_sensitive_text(message.strip())[:4000]

    def _consume_line(self, line: str) -> None:
        if not line.strip():
            return
        if len(line) > self.max_event_chars:
            self._store_malformed(line[: self.max_event_chars], reason="event exceeded size limit")
            self.truncated = True
            return
        try:
            parsed = json.loads(line)
        except (TypeError, ValueError):
            self._store_malformed(line, reason="invalid JSONL event")
            return
        if isinstance(parsed, Mapping):
            self._extract_metadata(parsed)
            safe = redact_sensitive_data(dict(parsed))
            if not isinstance(safe, dict):
                safe = {"type": "supabash.invalid_event"}
            self._store(safe)
            return
        self._store_malformed(
            json.dumps(redact_sensitive_data(parsed), ensure_ascii=False)[: self.max_event_chars],
            reason="non-object JSONL event",
        )

    def _store_malformed(self, line: str, *, reason: str) -> None:
        self.malformed_count += 1
        self._store(
            {
                "type": "supabash.malformed_event",
                "reason": reason,
                "preview": redact_sensitive_text(line[: self.max_event_chars]),
            }
        )

    def _store(self, event: Dict[str, Any]) -> None:
        self._event_count += 1
        if len(self._head) < self._head_limit:
            self._head.append(event)
        elif self._tail_limit:
            self._tail.append(event)
        if self._event_count > self.max_events:
            self.truncated = True

    def events(self) -> Tuple[Dict[str, Any], ...]:
        if self._event_count <= self._head_limit:
            return tuple(self._head)
        return tuple(self._head) + tuple(self._tail)

    @property
    def lifecycle_complete(self) -> bool:
        return bool(
            self.thread_started_seen
            and self.turn_completed_seen
            and not self.failure_event_seen
        )


_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: Dict[str, threading.Lock] = {}


class _LockTimeout(Exception):
    pass


class _LockCanceled(Exception):
    pass


class CodexRuntime:
    """Run the installed Codex CLI using a strict, testable subprocess boundary."""

    def __init__(self, config: Optional[CodexRuntimeConfig] = None) -> None:
        self.config = config or CodexRuntimeConfig()
        self._validate_config()
        self._cwd = Path(self.config.cwd or Path.cwd()).expanduser().resolve()
        self._cached_preflight: Optional[CodexPreflight] = None

    def _validate_config(self) -> None:
        if not str(self.config.command or "").strip():
            raise ValueError("Codex command must not be empty.")
        if "\x00" in self.config.command:
            raise ValueError("Codex command contains a NUL byte.")
        if self.config.sandbox not in {"read-only", "workspace-write", "danger-full-access"}:
            raise ValueError("Unsupported Codex sandbox mode.")
        for name in (
            "timeout_seconds",
            "preflight_timeout_seconds",
            "poll_interval_seconds",
            "terminate_grace_seconds",
        ):
            if float(getattr(self.config, name)) <= 0:
                raise ValueError(f"{name} must be greater than zero.")
        for name in ("max_events", "max_event_chars", "max_input_chars", "max_stderr_chars"):
            if int(getattr(self.config, name)) <= 0:
                raise ValueError(f"{name} must be greater than zero.")
        hard_limits = {
            "max_events": MAX_CODEX_EVENTS,
            "max_event_chars": MAX_CODEX_EVENT_CHARS,
            "max_stderr_chars": MAX_CODEX_STDERR_CHARS,
        }
        for name, limit in hard_limits.items():
            if int(getattr(self.config, name)) > limit:
                raise ValueError(f"{name} must not exceed {limit}.")
        if int(self.config.max_input_chars) > MAX_CODEX_INPUT_CHARS:
            raise ValueError(
                f"max_input_chars must not exceed {MAX_CODEX_INPUT_CHARS}."
            )
        for feature in self.config.disabled_features:
            normalized = str(feature or "").strip()
            if (
                not normalized
                or normalized.startswith("-")
                or any(char in normalized for char in ("\x00", "\r", "\n"))
            ):
                raise ValueError("Invalid disabled Codex feature name.")

    def _child_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        for key in tuple(env):
            if key.startswith("CODEX_") or key.startswith("CHATGPT_") or key.startswith("OPENAI_"):
                env.pop(key, None)
        env["CODEX_HOME"] = str(self._codex_home())
        env["SUPABASH_CODEX_CHILD"] = "1"
        return env

    def _resolved_command(self) -> Optional[str]:
        return shutil.which(self.config.command)

    def _global_instruction_violations(self) -> Tuple[str, ...]:
        """Return global instruction paths that could contaminate planner turns."""
        violations = []
        home = self._codex_home()
        for name in ("AGENTS.override.md", "AGENTS.md"):
            path = home / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                violations.append(str(path))
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 0:
                violations.append(str(path))
        return tuple(violations)

    def inspect(self, *, refresh: bool = False) -> CodexPreflight:
        """Inspect CLI version and login mode without launching a model turn."""
        if refresh:
            self._cached_preflight = None
        if self._cached_preflight is not None and self._cached_preflight.ready:
            return self._cached_preflight

        resolved = self._resolved_command()
        if not resolved:
            return CodexPreflight(
                command=self.config.command,
                installed=False,
                version=None,
                authenticated=False,
                auth_mode=None,
                is_chatgpt=False,
                ready=False,
                error=f"Codex executable not found: {self.config.command}",
            )

        env = self._child_env()
        timeout = self.config.preflight_timeout_seconds
        try:
            version_run = subprocess.run(
                [resolved, "--version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                timeout=timeout,
                env=env,
                cwd=str(self._cwd),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CodexPreflight(
                command=resolved,
                installed=True,
                version=None,
                authenticated=False,
                auth_mode=None,
                is_chatgpt=False,
                ready=False,
                error=redact_sensitive_text(f"Unable to inspect Codex: {exc}"),
            )

        version_text = (version_run.stdout or version_run.stderr or "").strip()
        version = redact_sensitive_text(version_text[:512]) or None
        if version_run.returncode != 0:
            return CodexPreflight(
                command=resolved,
                installed=True,
                version=version,
                authenticated=False,
                auth_mode=None,
                is_chatgpt=False,
                ready=False,
                error="Codex version check failed.",
            )

        required_exec_capabilities = (
            "resume",
            "--json",
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--output-schema",
            "--output-last-message",
        )
        try:
            help_run = subprocess.run(
                [resolved, "exec", "--help"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                timeout=timeout,
                env=env,
                cwd=str(self._cwd),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CodexPreflight(
                command=resolved,
                installed=True,
                version=version,
                authenticated=False,
                auth_mode=None,
                is_chatgpt=False,
                ready=False,
                error=redact_sensitive_text(f"Unable to inspect Codex exec capabilities: {exc}"),
                capabilities_ok=False,
                missing_capabilities=required_exec_capabilities,
            )
        help_text = "\n".join(filter(None, (help_run.stdout, help_run.stderr)))
        missing_capabilities = tuple(
            token for token in required_exec_capabilities if token not in help_text
        )
        if help_run.returncode != 0 or missing_capabilities:
            return CodexPreflight(
                command=resolved,
                installed=True,
                version=version,
                authenticated=False,
                auth_mode=None,
                is_chatgpt=False,
                ready=False,
                error=(
                    "Installed Codex CLI lacks required non-interactive capabilities: "
                    + ", ".join(missing_capabilities or ("exec --help",))
                ),
                capabilities_ok=False,
                missing_capabilities=missing_capabilities,
            )

        try:
            auth_run = subprocess.run(
                [resolved, "login", "status"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                timeout=timeout,
                env=env,
                cwd=str(self._cwd),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CodexPreflight(
                command=resolved,
                installed=True,
                version=version,
                authenticated=False,
                auth_mode=None,
                is_chatgpt=False,
                ready=False,
                error=redact_sensitive_text(f"Unable to inspect Codex login: {exc}"),
            )

        status_text = "\n".join(filter(None, (auth_run.stdout, auth_run.stderr))).strip()
        lowered = status_text.lower()
        authenticated = auth_run.returncode == 0 and "not logged in" not in lowered
        is_chatgpt = authenticated and "chatgpt" in lowered
        if is_chatgpt:
            auth_mode = "chatgpt"
        elif authenticated and "api key" in lowered:
            auth_mode = "api_key"
        elif authenticated and "access token" in lowered:
            auth_mode = "access_token"
        elif authenticated:
            auth_mode = "unknown"
        else:
            auth_mode = None

        instruction_files = self._global_instruction_violations()
        global_instructions_ok = not instruction_files
        ready = bool(
            authenticated
            and (is_chatgpt or not self.config.require_chatgpt)
            and global_instructions_ok
        )
        if not authenticated:
            error = "Codex is not authenticated. Run `codex login`."
        elif self.config.require_chatgpt and not is_chatgpt:
            error = "Codex must be logged in using a ChatGPT subscription."
        elif not global_instructions_ok:
            error = (
                "Codex global AGENTS instructions are not allowed for the Supabash planner. "
                "Empty the listed file(s) or configure a dedicated auth-only codex.codex_home."
            )
        else:
            error = None
        result = CodexPreflight(
            command=resolved,
            installed=True,
            version=version,
            authenticated=authenticated,
            auth_mode=auth_mode,
            is_chatgpt=is_chatgpt,
            ready=ready,
            error=error,
            global_instructions_ok=global_instructions_ok,
            global_instruction_files=instruction_files,
        )
        if result.ready:
            self._cached_preflight = result
        return result

    def preflight(self, *, refresh: bool = False) -> CodexPreflight:
        """Return a ready preflight result or raise a safe diagnostic error."""
        result = self.inspect(refresh=refresh)
        if not result.ready:
            raise CodexRuntimeError(result.error or "Codex preflight failed.")
        return result

    def _codex_home(self) -> Path:
        configured = self.config.codex_home or os.environ.get("CODEX_HOME") or "~/.codex"
        return Path(configured).expanduser().resolve()

    @contextmanager
    def _home_lock(self, deadline: float, cancel_event: Optional[Any]) -> Iterator[None]:
        home = self._codex_home()
        cache_home = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
        lock_root = cache_home.expanduser().resolve() / "supabash" / "locks"
        lock_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(lock_root, 0o700)
        except OSError:
            pass
        home_digest = hashlib.sha256(str(home).encode("utf-8", errors="replace")).hexdigest()[:16]
        user_id = getattr(os, "getuid", lambda: 0)()
        lock_path = lock_root / f"supabash-codex-{user_id}-{home_digest}.lock"
        key = str(lock_path)
        with _LOCKS_GUARD:
            local_lock = _PROCESS_LOCKS.setdefault(key, threading.Lock())

        while not local_lock.acquire(timeout=min(self.config.poll_interval_seconds, 0.1)):
            if self._cancel_requested(cancel_event):
                raise _LockCanceled
            if time.monotonic() >= deadline:
                raise _LockTimeout

        fd: Optional[int] = None
        locked = False
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError:
                    if self._cancel_requested(cancel_event):
                        raise _LockCanceled
                    if time.monotonic() >= deadline:
                        raise _LockTimeout
                    time.sleep(min(self.config.poll_interval_seconds, 0.1))
            yield
        finally:
            if fd is not None:
                if locked:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(fd)
            local_lock.release()

    @staticmethod
    def _cancel_requested(cancel_event: Optional[Any]) -> bool:
        if cancel_event is None:
            return False
        try:
            return bool(cancel_event.is_set())
        except Exception:
            return False

    @staticmethod
    def _private_write(path: Path, content: str) -> None:
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()

    def _build_argv(
        self,
        executable: str,
        schema_path: Path,
        output_path: Path,
        thread_id: Optional[str],
    ) -> Tuple[str, ...]:
        common = [
            "--sandbox",
            self.config.sandbox,
            "--cd",
            str(self._cwd),
            "--skip-git-repo-check",
        ]
        if self.config.ignore_user_config:
            common.append("--ignore-user-config")
        common.append("--ignore-rules")
        common.append("--strict-config")
        if self.config.model:
            common.extend(("--model", self.config.model))
        for override in FORCED_CONFIG_OVERRIDES:
            if override.startswith("web_search=") and not self.config.disable_web_search:
                continue
            common.extend(("--config", override))
        for feature in self.config.disabled_features:
            common.extend(("--disable", str(feature)))

        if thread_id is None:
            argv = [
                executable,
                "exec",
                *common,
                "--json",
                "--color",
                "never",
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(output_path),
            ]
            if not self.config.persistent_thread:
                argv.append("--ephemeral")
            argv.append("-")
            return tuple(argv)

        return (
            executable,
            "exec",
            *common,
            "resume",
            "--json",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
            thread_id,
            "-",
        )

    @staticmethod
    def _terminate(proc: subprocess.Popen[bytes], grace: float) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                proc.terminate()
            except OSError:
                pass
        try:
            proc.wait(timeout=grace)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=grace)
        except (OSError, subprocess.TimeoutExpired):
            pass

    @staticmethod
    def _read_stream(
        stream: Any,
        collector: Any,
        state: Dict[str, str],
        label: str,
    ) -> None:
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                collector.feed(chunk)
        except Exception as exc:
            state["error"] = redact_sensitive_text(
                f"Codex {label} reader failed: {exc.__class__.__name__}"
            )
        finally:
            if isinstance(collector, _JsonlCapture):
                try:
                    collector.finish()
                except Exception as exc:
                    state["error"] = redact_sensitive_text(
                        f"Codex {label} parser failed: {exc.__class__.__name__}"
                    )
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    @staticmethod
    def _write_stream(stream: Any, payload: bytes, state: Dict[str, str]) -> None:
        try:
            written = stream.write(payload)
            stream.flush()
            if written is not None and int(written) != len(payload):
                state["error"] = "Codex prompt was not fully delivered."
        except (BrokenPipeError, OSError, ValueError) as exc:
            state["error"] = redact_sensitive_text(
                f"Unable to deliver the Codex prompt: {exc.__class__.__name__}"
            )
        finally:
            try:
                stream.close()
            except OSError:
                pass

    @staticmethod
    def _kill_lingering_group(pid: int, grace: float) -> None:
        try:
            os.killpg(pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            return
        time.sleep(min(max(grace, 0.01), 0.2))
        try:
            os.killpg(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    def _empty_result(
        self,
        *,
        start: float,
        argv: Tuple[str, ...] = (),
        return_code: int = -1,
        error: str,
        timed_out: bool = False,
        canceled: bool = False,
    ) -> CodexRunResult:
        return CodexRunResult(
            success=False,
            return_code=return_code,
            thread_id=None,
            structured_output=None,
            final_text="",
            events=(),
            usage={},
            stderr="",
            error=redact_sensitive_text(error),
            timed_out=timed_out,
            canceled=canceled,
            duration_seconds=max(0.0, time.monotonic() - start),
            argv=argv,
            malformed_event_count=0,
            stdout_truncated=False,
            stderr_truncated=False,
            policy_event_types=(),
            protocol_event_count=0,
            lifecycle_complete=False,
            stream_incomplete=False,
        )

    def run(
        self,
        prompt: str,
        output_schema: Mapping[str, Any],
        thread_id: Optional[str] = None,
        cancel_event: Optional[Any] = None,
    ) -> CodexRunResult:
        """Run one schema-constrained Codex turn and return redacted evidence."""
        start = time.monotonic()
        if os.environ.get("SUPABASH_CODEX_CHILD"):
            raise CodexRuntimeError("Refusing to launch Codex recursively from a Codex child process.")
        ambient_context = ambient_codex_context_keys()
        if ambient_context:
            raise CodexRuntimeError(
                "Refusing to launch a nested Codex planner with ambient Codex task context. "
                "Run Supabash from a standalone terminal."
            )
        instruction_files = self._global_instruction_violations()
        if instruction_files:
            raise CodexRuntimeError(
                "Refusing Codex planner launch while global AGENTS instructions are present. "
                "Use an auth-only Codex home."
            )
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Codex prompt must be a non-empty string.")
        if len(prompt) > self.config.max_input_chars:
            raise ValueError(
                f"Codex prompt exceeds max_input_chars ({self.config.max_input_chars})."
            )
        if not isinstance(output_schema, Mapping):
            raise TypeError("output_schema must be a mapping.")
        if not self._cwd.is_dir():
            raise CodexRuntimeError(f"Codex working directory does not exist: {self._cwd}")
        if thread_id is not None:
            thread_id = str(thread_id).strip()
            if not self.config.persistent_thread:
                raise ValueError("Cannot resume a thread when persistent_thread is disabled.")
            if (
                not thread_id
                or len(thread_id) > 256
                or thread_id.startswith("-")
                or any(char in thread_id for char in ("\x00", "\r", "\n"))
            ):
                raise ValueError("Invalid Codex thread_id.")

        try:
            schema_text = json.dumps(output_schema, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"output_schema is not JSON serializable: {exc}") from exc

        if self._cancel_requested(cancel_event):
            return self._empty_result(
                start=start,
                error="Codex run canceled before launch.",
                return_code=-2,
                canceled=True,
            )
        preflight = self.preflight()
        deadline = start + self.config.timeout_seconds

        private_temp_parent = "/tmp" if os.name == "posix" and Path("/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(
            prefix="supabash-codex-",
            dir=private_temp_parent,
        ) as temp_name:
            temp_dir = Path(temp_name)
            try:
                os.chmod(temp_dir, 0o700)
            except OSError:
                pass
            schema_path = temp_dir / "output-schema.json"
            output_path = temp_dir / "last-message.json"
            self._private_write(schema_path, schema_text)
            self._private_write(output_path, "")
            argv = self._build_argv(preflight.command, schema_path, output_path, thread_id)

            try:
                lock_context = self._home_lock(deadline, cancel_event)
                with lock_context:
                    return self._run_locked(
                        argv=argv,
                        prompt=prompt,
                        output_path=output_path,
                        deadline=deadline,
                        start=start,
                        cancel_event=cancel_event,
                    )
            except _LockCanceled:
                return self._empty_result(
                    start=start,
                    argv=argv,
                    error="Codex run canceled while waiting for the runtime lock.",
                    return_code=-2,
                    canceled=True,
                )
            except _LockTimeout:
                return self._empty_result(
                    start=start,
                    argv=argv,
                    error="Codex run timed out while waiting for the runtime lock.",
                    timed_out=True,
                )

    def _run_locked(
        self,
        *,
        argv: Tuple[str, ...],
        prompt: str,
        output_path: Path,
        deadline: float,
        start: float,
        cancel_event: Optional[Any],
    ) -> CodexRunResult:
        stdout_capture = _JsonlCapture(self.config.max_events, self.config.max_event_chars)
        stderr_capture = _BoundedTextCapture(self.config.max_stderr_chars)
        try:
            proc = subprocess.Popen(
                list(argv),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self._cwd),
                env=self._child_env(),
                start_new_session=True,
            )
        except FileNotFoundError:
            return self._empty_result(
                start=start,
                argv=argv,
                return_code=127,
                error=f"Codex executable not found: {argv[0]}",
            )
        except OSError as exc:
            return self._empty_result(
                start=start,
                argv=argv,
                return_code=126,
                error=f"Unable to launch Codex: {exc}",
            )

        assert proc.stdout is not None
        assert proc.stderr is not None
        stdout_state = {"error": ""}
        stderr_state = {"error": ""}
        stdout_thread = threading.Thread(
            target=self._read_stream,
            args=(proc.stdout, stdout_capture, stdout_state, "stdout"),
            name="supabash-codex-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._read_stream,
            args=(proc.stderr, stderr_capture, stderr_state, "stderr"),
            name="supabash-codex-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        assert proc.stdin is not None
        writer_state = {"error": ""}
        writer_thread = threading.Thread(
            target=self._write_stream,
            args=(proc.stdin, prompt.encode("utf-8"), writer_state),
            name="supabash-codex-stdin",
            daemon=True,
        )
        writer_thread.start()

        timed_out = False
        canceled = False
        while proc.poll() is None:
            if self._cancel_requested(cancel_event):
                canceled = True
                self._terminate(proc, self.config.terminate_grace_seconds)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                self._terminate(proc, self.config.terminate_grace_seconds)
                break
            time.sleep(self.config.poll_interval_seconds)

        if proc.poll() is None:
            self._terminate(proc, self.config.terminate_grace_seconds)
        writer_thread.join(timeout=self.config.terminate_grace_seconds)
        stdout_thread.join(timeout=self.config.terminate_grace_seconds)
        stderr_thread.join(timeout=self.config.terminate_grace_seconds)
        reader_error = stdout_state.get("error") or stderr_state.get("error") or ""
        stream_incomplete = bool(
            writer_thread.is_alive()
            or stdout_thread.is_alive()
            or stderr_thread.is_alive()
            or reader_error
        )
        if stream_incomplete:
            self._kill_lingering_group(proc.pid, self.config.terminate_grace_seconds)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
            writer_thread.join(timeout=self.config.terminate_grace_seconds)
            stdout_thread.join(timeout=self.config.terminate_grace_seconds)
            stderr_thread.join(timeout=self.config.terminate_grace_seconds)
        reader_error = stdout_state.get("error") or stderr_state.get("error") or reader_error
        collectors_still_active = bool(stdout_thread.is_alive() or stderr_thread.is_alive())

        stderr = "" if collectors_still_active else redact_sensitive_text(stderr_capture.text()).strip()
        if canceled:
            return_code = -2
        elif timed_out:
            return_code = -1
        else:
            return_code = proc.returncode if proc.returncode is not None else -1

        raw_final = ""
        final_limit = max(self.config.max_event_chars, self.config.max_input_chars * 4)
        try:
            with output_path.open("r", encoding="utf-8", errors="replace") as handle:
                raw_final = handle.read(final_limit + 1)
        except OSError:
            raw_final = stdout_capture.last_agent_text
        if not raw_final.strip() and stdout_capture.last_agent_text:
            raw_final = stdout_capture.last_agent_text
        final_too_large = len(raw_final) > final_limit
        if final_too_large:
            raw_final = raw_final[:final_limit]

        structured_output: Any = None
        structured_valid = False
        final_text = ""
        if raw_final.strip() and not final_too_large:
            try:
                structured_output = redact_sensitive_data(json.loads(raw_final))
                structured_valid = True
                final_text = json.dumps(
                    structured_output,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            except (TypeError, ValueError):
                structured_output = None
                final_text = redact_sensitive_text(raw_final).strip()
        else:
            final_text = redact_sensitive_text(raw_final).strip()

        if canceled:
            error = "Codex run canceled."
        elif timed_out:
            error = f"Codex run timed out after {self.config.timeout_seconds:g} seconds."
        elif stream_incomplete or writer_state.get("error"):
            error = (
                writer_state.get("error")
                or reader_error
                or "Codex subprocess streams did not reach EOF."
            )
        elif return_code != 0:
            error = f"Codex exited with status {return_code}."
            if stdout_capture.error_message:
                error = f"{error} {stdout_capture.error_message}"
        elif stdout_capture.malformed_count:
            error = "Codex emitted malformed JSONL; the turn was rejected."
        elif stdout_capture.truncated:
            error = "Codex JSONL exceeded capture limits; the turn was rejected."
        elif stdout_capture.failure_event_seen:
            error = stdout_capture.error_message or "Codex emitted a failed terminal event."
        elif not stdout_capture.lifecycle_complete:
            error = "Codex JSONL did not contain a complete successful lifecycle."
        elif final_too_large:
            error = "Codex final response exceeded the configured size limit."
        elif not structured_valid:
            error = "Codex did not return valid structured JSON."
        else:
            error = None

        return CodexRunResult(
            success=(
                return_code == 0
                and structured_valid
                and not timed_out
                and not canceled
                and not stream_incomplete
                and not writer_state.get("error")
                and stdout_capture.malformed_count == 0
                and not stdout_capture.truncated
                and stdout_capture.lifecycle_complete
            ),
            return_code=return_code,
            thread_id=None if collectors_still_active else stdout_capture.thread_id,
            structured_output=structured_output,
            final_text=final_text,
            events=() if collectors_still_active else stdout_capture.events(),
            usage={} if collectors_still_active else dict(stdout_capture.usage),
            stderr=stderr,
            error=error,
            timed_out=timed_out,
            canceled=canceled,
            duration_seconds=max(0.0, time.monotonic() - start),
            argv=argv,
            malformed_event_count=stdout_capture.malformed_count,
            stdout_truncated=stdout_capture.truncated,
            stderr_truncated=stderr_capture.truncated,
            policy_event_types=(
                () if collectors_still_active else tuple(sorted(stdout_capture.policy_event_types))
            ),
            protocol_event_count=stdout_capture.object_event_count,
            lifecycle_complete=stdout_capture.lifecycle_complete,
            stream_incomplete=stream_incomplete,
        )


__all__ = [
    "CodexPreflight",
    "CodexRunResult",
    "CodexRuntime",
    "CodexRuntimeConfig",
    "CodexRuntimeError",
    "MAX_CODEX_EVENT_CHARS",
    "MAX_CODEX_EVENTS",
    "MAX_CODEX_INPUT_CHARS",
    "MAX_CODEX_STDERR_CHARS",
    "ambient_codex_context_keys",
]
