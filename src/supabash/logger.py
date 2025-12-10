import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Constants
APP_NAME = "supabash"
LOG_DIR = Path.home() / f".{APP_NAME}" / "logs"
LOG_FILE = LOG_DIR / "debug.log"

def setup_logger(name: str = APP_NAME) -> logging.Logger:
    """
    Sets up a rotating file logger for the application.
    Logs are stored in ~/.supabash/logs/debug.log
    """
    # Create the log directory if it doesn't exist
    if not LOG_DIR.exists():
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
        except OSError as e:
            # If we can't create the log dir, fallback to a basic stderr config or just print
            print(f"Error creating log directory {LOG_DIR}: {e}")
            return logging.getLogger(name)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Prevent adding multiple handlers if setup_logger is called multiple times
    if logger.handlers:
        return logger

    # Create rotating file handler (5MB, keep last 3 files)
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)

        # Add handler to logger
        logger.addHandler(file_handler)
        
    except Exception as e:
        print(f"Failed to setup file logging: {e}")

    return logger
