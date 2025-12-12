import threading
import time
import unittest

from supabash.audit import AuditOrchestrator


class BlockingNmap:
    def __init__(self, started: threading.Event, allow_finish: threading.Event):
        self.started = started
        self.allow_finish = allow_finish

    def scan(self, *args, **kwargs):
        self.started.set()
        self.allow_finish.wait(timeout=2.0)
        return {"success": True, "scan_data": {"hosts": []}}


class SignalScanner:
    def __init__(self, started: threading.Event, name: str):
        self.started = started
        self.name = name

    def scan(self, *args, **kwargs):
        self.started.set()
        time.sleep(0.02)
        return {"success": True, "data": {"tool": self.name}}


class FakeLLM:
    def chat(self, messages, temperature=0.2):
        return '{"summary":"ok","findings":[]}'


class TestAuditParallelWeb(unittest.TestCase):
    def test_parallel_web_overlaps_with_nmap_for_url_targets(self):
        nmap_started = threading.Event()
        allow_nmap_finish = threading.Event()
        whatweb_started = threading.Event()

        scanners = {
            "nmap": BlockingNmap(nmap_started, allow_nmap_finish),
            "whatweb": SignalScanner(whatweb_started, "whatweb"),
            "nuclei": SignalScanner(threading.Event(), "nuclei"),
            "gobuster": SignalScanner(threading.Event(), "gobuster"),
            "sqlmap": SignalScanner(threading.Event(), "sqlmap"),
            "trivy": SignalScanner(threading.Event(), "trivy"),
            "supabase_rls": type("Noop", (), {"check": lambda self, url: {"success": True, "data": {}}})(),
        }

        orch = AuditOrchestrator(scanners=scanners, llm_client=FakeLLM())
        result_holder = {}

        def run():
            result_holder["report"] = orch.run(
                "http://127.0.0.1:8080",
                output=None,
                parallel_web=True,
                max_workers=3,
            )

        t = threading.Thread(target=run, daemon=True)
        t.start()

        self.assertTrue(nmap_started.wait(timeout=0.5), "nmap never started")
        self.assertTrue(
            whatweb_started.wait(timeout=0.5),
            "whatweb did not start before nmap finished (expected overlap)",
        )

        allow_nmap_finish.set()
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive(), "audit did not complete")

        report = result_holder["report"]
        tools = {r.get("tool") for r in report.get("results", []) if isinstance(r, dict)}
        self.assertIn("nmap", tools)
        self.assertIn("whatweb", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("gobuster", tools)

