from __future__ import annotations


def normalize_target_token(token: str) -> str:
    """
    Normalize common key=value forms users paste into chat.

    Examples:
      - "localhost" -> "localhost"
      - "target=localhost" -> "localhost"
      - "host=10.0.0.1" -> "10.0.0.1"
      - "url=http://127.0.0.1" -> "http://127.0.0.1"
    """
    token = (token or "").strip()
    if not token:
        return token

    lower = token.lower()
    for prefix in ("target=", "host=", "url="):
        if lower.startswith(prefix):
            return token[len(prefix) :]

    if "=" in token:
        key, value = token.split("=", 1)
        if key.strip().lower() in ("target", "host", "url"):
            return value.strip()

    return token

