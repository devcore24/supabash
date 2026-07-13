from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


REDACTED = "<redacted>"
_GENERIC_SECRET_FLAGS = {
    "--api-key",
    "--api_key",
    "--api-token",
    "--api_token",
    "--authorization",
    "--bearer-token",
    "--cookie",
    "--hash",
    "--hashes",
    "--key",
    "--password",
    "--passwd",
    "--secret",
    "--token",
}
_TOOL_SHORT_SECRET_FLAGS = {
    "hydra": {"-p", "-P"},
    "medusa": {"-p", "-P"},
    "crackmapexec": {"-p", "-H"},
    "cme": {"-p", "-H"},
    "netexec": {"-p", "-H"},
    "nxc": {"-p", "-H"},
    "wpscan": set(),
}
_SECRET_KEY_RE = re.compile(
    r"(?i)^(?P<key>[a-z0-9_.-]*(?:api[_-]?key|api[_-]?token|authorization|"
    r"bearer[_-]?token|cookie|hashes?|password|passwd|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|private[_-]?key|"
    r"secret[_-]?access[_-]?key|service[_-]?role[_-]?key|secret|token))"
    r"(?P<sep>=|:)(?P<value>.+)$"
)
_URL_USERINFO_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@"
)
_SENSITIVE_FIELD_NAMES = {
    "accesstoken",
    "apikey",
    "apitoken",
    "authorization",
    "bearertoken",
    "clientsecret",
    "cookie",
    "hash",
    "hashes",
    "password",
    "passwd",
    "privatekey",
    "refreshtoken",
    "secret",
    "secretaccesskey",
    "servicerolekey",
    "setcookie",
    "token",
}
_SECRET_LABEL = (
    r"password|passwd|api[_-]?key|api[_-]?token|bearer[_-]?token|"
    r"cookie|set-cookie|hashes?|client[_-]?secret|private[_-]?key|"
    r"secret[_-]?access[_-]?key|service[_-]?role[_-]?key|secret|token"
)
_QUOTED_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>['\"]?(?:{_SECRET_LABEL})['\"]?\s*[:=]\s*)"
    r"(?P<quote>['\"])(?P<value>.*?)(?P=quote)"
)
_BEARER_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>\bauthorization\s*[:=]\s*bearer\s+)(?P<value>[^\s,;]+)"
)
_BASIC_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>\bauthorization\s*[:=]\s*basic\s+)(?P<value>[^\s,;]+)"
)
_GENERIC_AUTH_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>\bauthorization\s*[:=](?!\s*(?:bearer|basic)\b)\s*)(?P<value>[^\r\n]+)"
)
_UNQUOTED_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>(?<![?&])\b(?:{_SECRET_LABEL})\s*[:=]\s*)(?P<value>[^\r\n\]\}}]+)"
)
_CREDENTIAL_SUCCESS_RE = re.compile(
    r"(?im)(?P<prefix>\[\+\]\s+(?:(?:[^\\\s]+)\\)?[^:\s]+:)(?P<value>[^\r\n]+)"
)
_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{2,}\b")
_URL_QUERY_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>(?:[?&]|&amp;)(?:api[_-]?key|apikey|api[_-]?token|"
    r"access[_-]?token|refresh[_-]?token|token|signature|x-amz-signature|"
    r"x-amz-security-token)=)(?P<value>[^&#\s'\"<>]+)"
)
_SUPABASE_SECRET_RE = re.compile(r"\bsb_secret_[a-zA-Z0-9_-]+\b")



def _tool_name(argv: Sequence[str]) -> str:
    if not argv:
        return ""
    return Path(str(argv[0])).name.strip().lower()


def _redact_url_userinfo(value: str) -> Tuple[str, bool]:
    text = str(value)

    def replacement(match: re.Match[str]) -> str:
        matched = match.group(0)
        scheme, userinfo = matched[:-1].split("://", 1)
        username = userinfo.rsplit(":", 1)[0] or "user"
        return f"{scheme}://{username}:{REDACTED}@"

    safe, count = _URL_USERINFO_RE.subn(replacement, text)
    return safe, bool(count)


def redact_argv(argv: Sequence[Any]) -> Tuple[List[str], bool]:
    """Return a display-safe argv copy and whether any value was redacted."""
    values = [str(item) for item in list(argv or [])]
    tool = _tool_name(values)
    short_flags = _TOOL_SHORT_SECRET_FLAGS.get(tool, set())
    redacted: List[str] = []
    changed = False
    hide_next = False

    for raw in values:
        value = str(raw)
        if hide_next:
            redacted.append(REDACTED)
            hide_next = False
            changed = changed or value != REDACTED
            continue

        lowered = value.lower()
        if lowered in _GENERIC_SECRET_FLAGS or value in short_flags:
            redacted.append(value)
            hide_next = True
            continue

        inline_redacted = False
        for flag in _GENERIC_SECRET_FLAGS:
            for separator in ("=", ":"):
                prefix = f"{flag}{separator}"
                if lowered.startswith(prefix) and len(value) > len(prefix):
                    redacted.append(f"{value[:len(prefix)]}{REDACTED}")
                    changed = True
                    inline_redacted = True
                    break
            if inline_redacted:
                break
        if inline_redacted:
            continue

        short_match = next(
            (flag for flag in short_flags if value.startswith(flag) and len(value) > len(flag)),
            None,
        )
        if short_match:
            redacted.append(f"{short_match}{REDACTED}")
            changed = True
            continue

        key_match = _SECRET_KEY_RE.match(value)
        if key_match and key_match.group("value") != REDACTED:
            redacted.append(f"{key_match.group('key')}{key_match.group('sep')}{REDACTED}")
            changed = True
            continue

        safe_url, url_changed = _redact_url_userinfo(value)
        safe_url, query_count = _URL_QUERY_SECRET_RE.subn(
            lambda match: f"{match.group('prefix')}{REDACTED}",
            safe_url,
        )
        safe_url, jwt_count = _JWT_RE.subn(REDACTED, safe_url)
        safe_url, supabase_count = _SUPABASE_SECRET_RE.subn(REDACTED, safe_url)
        redacted.append(safe_url)
        changed = changed or url_changed or bool(
            query_count
            or jwt_count
            or supabase_count
        )

    return redacted, changed


def redact_command(command: Sequence[Any]) -> str:
    safe_argv, _ = redact_argv(command)
    return shlex.join(safe_argv)


def redact_command_text(command: Any) -> str:
    text = str(command or "").strip()
    if not text:
        return ""
    try:
        argv = shlex.split(text)
    except ValueError:
        argv = text.split()
    return redact_command(argv)


def command_contains_unredacted_secret(command: Any) -> bool:
    text = str(command or "").strip()
    if not text:
        return False
    try:
        argv = shlex.split(text)
    except ValueError:
        argv = text.split()
    _, changed = redact_argv(argv)
    return changed


def _looks_redacted_or_masked(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    if text.lower() == REDACTED:
        return True
    if text == "***":
        return True
    if re.fullmatch(r"[^*\s]{1,2}\*{3}[^*\s]{1,2}", text):
        return True
    return bool(re.fullmatch(r".{6}….{4}", text))


def _replace_secret_match(match: re.Match[str], *, quoted: bool = False) -> str:
    if _looks_redacted_or_masked(match.group("value")):
        return match.group(0)
    if quoted:
        quote = match.group("quote")
        return f"{match.group('prefix')}{quote}{REDACTED}{quote}"
    return f"{match.group('prefix')}{REDACTED}"


def redact_sensitive_text(value: Any) -> str:
    """Redact common credential material embedded in persisted free-form text."""
    text = str(value or "")
    safe, _ = _redact_url_userinfo(text)
    safe = _URL_QUERY_SECRET_RE.sub(
        _replace_secret_match,
        safe,
    )
    safe = _BEARER_SECRET_RE.sub(
        _replace_secret_match,
        safe,
    )
    safe = _BASIC_SECRET_RE.sub(
        _replace_secret_match,
        safe,
    )
    safe = _GENERIC_AUTH_SECRET_RE.sub(
        _replace_secret_match,
        safe,
    )
    safe = _QUOTED_SECRET_RE.sub(
        lambda match: _replace_secret_match(match, quoted=True),
        safe,
    )
    safe = _UNQUOTED_SECRET_RE.sub(
        _replace_secret_match,
        safe,
    )
    safe = _CREDENTIAL_SUCCESS_RE.sub(
        _replace_secret_match,
        safe,
    )
    return _SUPABASE_SECRET_RE.sub(REDACTED, _JWT_RE.sub(REDACTED, safe))


def _normalized_field_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def redact_sensitive_data(value: Any, *, _command_context: bool = False) -> Any:
    """Return a recursively sanitized copy suitable for reports and artifacts."""
    if isinstance(value, dict):
        sanitized: Dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = _normalized_field_name(key)
            if normalized_key in _SENSITIVE_FIELD_NAMES and item not in (None, ""):
                sanitized[key] = REDACTED
                continue
            sanitized[key] = redact_sensitive_data(
                item,
                _command_context=(
                    _command_context or normalized_key in {"command", "commands"}
                ),
            )
        return sanitized
    if isinstance(value, list):
        return [
            redact_sensitive_data(item, _command_context=_command_context)
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            redact_sensitive_data(item, _command_context=_command_context)
            for item in value
        )
    if isinstance(value, str):
        if _command_context:
            return redact_sensitive_text(redact_command_text(value))
        return redact_sensitive_text(value)
    return value


def find_sensitive_data_paths(
    value: Any,
    *,
    path: str = "$",
    limit: int = 20,
) -> List[str]:
    """Return paths containing credential material without exposing the values."""
    findings: List[str] = []

    def visit(item: Any, current_path: str) -> None:
        if len(findings) >= max(0, int(limit)):
            return
        if isinstance(item, dict):
            for key, child in item.items():
                normalized_key = _normalized_field_name(key)
                child_path = f"{current_path}.{key}"
                if normalized_key in {"command", "commands"}:
                    continue
                if normalized_key in _SENSITIVE_FIELD_NAMES and child not in (None, ""):
                    if not _looks_redacted_or_masked(child):
                        findings.append(child_path)
                    continue
                visit(child, child_path)
            return
        if isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                visit(child, f"{current_path}[{index}]")
            return
        if isinstance(item, str) and redact_sensitive_text(item) != item:
            findings.append(current_path)

    visit(value, path)
    return findings
