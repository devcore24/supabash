import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from supabash.redaction import redact_sensitive_text
from supabash.secure_io import restrict_file_permissions

# Constants
APP_NAME = "supabash"
LOG_DIR = Path(os.getenv("SUPABASH_LOG_DIR", Path.cwd()))
LOG_FILE = LOG_DIR / "debug.log"
# Shared rotating handler to prevent duplicates across modules
_file_handler = None

class _SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_sensitive_text(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


class _SecureRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        stream = super()._open()
        restrict_file_permissions(self.baseFilename)
        return stream


class _SensitiveDataFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_sensitive_text(super().format(record))



def _resolve_level(level_name: str) -> int:
    """Convert a string log level to logging module constant."""
    if isinstance(level_name, int):
        return level_name
    if not level_name:
        return logging.INFO
    level = getattr(logging, str(level_name).upper(), None)
    return level if isinstance(level, int) else logging.INFO

def setup_logger(name: str = APP_NAME, log_level: str = None) -> logging.Logger:
    """
    Sets up a rotating file logger for the application.
    Logs are stored in ./debug.log by default (override with SUPABASH_LOG_DIR).
    """
    effective_level = _resolve_level(log_level or os.getenv("SUPABASH_LOG_LEVEL", "INFO"))

    # Create the log directory if it doesn't exist
    if not LOG_DIR.exists():
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
        except OSError as e:
            # If we can't create the log dir, fallback to a basic stderr config or just print
            print(f"Error creating log directory {LOG_DIR}: {e}")
            return logging.getLogger(name)

    global _file_handler

    # Configure a single base logger for all supabash.* loggers
    base_logger = logging.getLogger(APP_NAME)
    base_logger.setLevel(effective_level)
    base_logger.propagate = False  # stop bubbling to root (avoids duplicate handlers elsewhere)

    # Create rotating file handler (5MB, keep last 3 files) once
    if _file_handler is None:
        try:
            _file_handler = _SecureRotatingFileHandler(
                LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
            )
            formatter = _SensitiveDataFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            _file_handler.setFormatter(formatter)
            base_logger.addHandler(_file_handler)
            _file_handler.addFilter(_SensitiveDataFilter())
        except Exception as e:
            print(f"Failed to setup file logging: {e}")
    # Keep handler level in sync with config
    if _file_handler is not None:
        _file_handler.setLevel(effective_level)

    logger = logging.getLogger(name)
    logger.setLevel(effective_level)
    if logger is not base_logger:
        logger.propagate = True  # rely on base handler only

    return logger
