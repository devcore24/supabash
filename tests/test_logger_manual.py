import unittest
import sys
import os
import logging
from pathlib import Path
from tempfile import TemporaryDirectory

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import supabash.logger as logger_mod


class TestLogger(unittest.TestCase):
    def test_logging_writes_to_file(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            log_file = tmp_path / "debug.log"

            # Reset shared handler and base logger handlers
            base_logger = logging.getLogger(logger_mod.APP_NAME)
            for h in list(base_logger.handlers):
                base_logger.removeHandler(h)
                try:
                    h.close()
                except Exception:
                    pass

            old_log_dir = logger_mod.LOG_DIR
            old_log_file = logger_mod.LOG_FILE
            old_handler = getattr(logger_mod, "_file_handler", None)

            try:
                logger_mod.LOG_DIR = tmp_path
                logger_mod.LOG_FILE = log_file
                logger_mod._file_handler = None

                logger = logger_mod.setup_logger("supabash.test", log_level="DEBUG")
                logger.debug("test debug message")

                # Flush handlers
                for h in logging.getLogger(logger_mod.APP_NAME).handlers:
                    try:
                        h.flush()
                    except Exception:
                        pass

                self.assertTrue(log_file.exists())
                content = log_file.read_text()
                self.assertIn("test debug message", content)
            finally:
                logger_mod.LOG_DIR = old_log_dir
                logger_mod.LOG_FILE = old_log_file
                logger_mod._file_handler = old_handler


if __name__ == "__main__":
    unittest.main()
