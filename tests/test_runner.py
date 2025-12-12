import unittest
import sys
import os
import shutil
import threading
import time

# Add src to python path to import supabash modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.runner import CommandRunner

class TestCommandRunner(unittest.TestCase):
    def setUp(self):
        self.runner = CommandRunner()

    def test_run_echo_success(self):
        """Test a simple echo command."""
        result = self.runner.run(['echo', 'hello'])
        self.assertTrue(result.success)
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.stdout, 'hello')
        self.assertEqual(result.stderr, '')

    def test_run_accepts_bytes_command_items(self):
        result = self.runner.run([b"/bin/echo", b"hello"])
        self.assertTrue(result.success)
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.stdout, "hello")

    def test_run_collects_output_across_timeouts(self):
        result = self.runner.run(["bash", "-lc", "echo hi; sleep 0.2; echo bye"], timeout=5)
        self.assertTrue(result.success)
        self.assertIn("hi", result.stdout)
        self.assertIn("bye", result.stdout)

    def test_run_command_failure(self):
        """Test a command that returns a non-zero exit code."""
        # 'ls' of a non-existent file usually returns 2 or 1
        result = self.runner.run(['ls', 'non_existent_file_xyz_123'])
        self.assertFalse(result.success)
        self.assertNotEqual(result.return_code, 0)
        # Stderr should contain some error message
        self.assertTrue(len(result.stderr) > 0)

    def test_run_timeout(self):
        """Test that the timeout works."""
        # Sleep for 2 seconds, but timeout after 1 second
        result = self.runner.run(['sleep', '2'], timeout=1)
        self.assertFalse(result.success)
        self.assertEqual(result.return_code, -1)
        self.assertIn("timed out", result.error_message)

    def test_command_not_found(self):
        """Test execution of a non-existent binary."""
        result = self.runner.run(['non_existent_command_abc'])
        self.assertFalse(result.success)
        self.assertEqual(result.return_code, 127)
        self.assertIn("Executable not found", result.error_message)

    def test_cancel_event_stops_command(self):
        cancel = threading.Event()
        def cancel_soon():
            time.sleep(0.1)
            cancel.set()
        t = threading.Thread(target=cancel_soon, daemon=True)
        t.start()
        result = self.runner.run(["sleep", "5"], cancel_event=cancel)
        self.assertFalse(result.success)
        self.assertTrue(getattr(result, "canceled", False))
        self.assertEqual(result.return_code, -2)

if __name__ == '__main__':
    unittest.main()
