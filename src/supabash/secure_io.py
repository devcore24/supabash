from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union


PathLike = Union[str, os.PathLike[str]]


def restrict_file_permissions(path: PathLike, mode: int = 0o600) -> None:
    """Best-effort restriction for files that may contain audit or credential data."""
    try:
        os.chmod(Path(path), mode)
    except OSError:
        pass


def atomic_write_text(
    path: PathLike,
    content: str,
    *,
    encoding: str = "utf-8",
    mode: int = 0o600,
) -> None:
    """Atomically replace a text file with owner-only permissions by default."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, destination)
        restrict_file_permissions(destination, mode)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
