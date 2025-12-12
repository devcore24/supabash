import time
import unittest

from supabash.jobs import JobManager


class TestJobs(unittest.TestCase):
    def test_job_manager_single_active(self):
        mgr = JobManager()
        job = mgr.start_job("test", "t", lambda: time.sleep(0.2) or 123)
        self.assertIsNotNone(job)
        with self.assertRaises(RuntimeError):
            mgr.start_job("test2", "t2", lambda: 456)
        # wait for completion
        for _ in range(50):
            done = mgr.take_result_if_done()
            if done:
                break
            time.sleep(0.01)
        self.assertIsNotNone(done)
        self.assertEqual(done["result"], 123)

    def test_cancel_sets_flag(self):
        mgr = JobManager()
        job = mgr.start_job("test", "t", lambda: time.sleep(0.2))
        ok = mgr.cancel_active()
        self.assertTrue(ok)
        self.assertTrue(job.cancel_event.is_set())


if __name__ == "__main__":
    unittest.main()
