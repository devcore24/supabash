import json
import os
import sys
import unittest

from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from supabash.ai_audit import AIAuditOrchestrator
from tests.test_artifacts import artifact_path


class FakeNmapScanner:
    def scan(self, target, arguments=None, **kwargs):
        return {
            "success": True,
            "command": f"nmap {target} -oX - -sV --script ssl-enum-ciphers -p-",
            "scan_data": {
                "hosts": [
                    {
                        "ip": "127.0.0.1",
                        "ports": [
                            {
                                "port": 8080,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "nginx",
                                "version": "1.0",
                            },
                            {
                                "port": 9090,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "prometheus",
                                "version": "2.0",
                            },
                            {
                                "port": 4006,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "express",
                                "version": "4",
                            },
                            {
                                "port": 19090,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "custom-http",
                                "version": "1",
                            },
                            {
                                "port": 42037,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "express",
                                "version": "4",
                            },
                        ],
                    }
                ]
            },
        }


class FakeHttpxScanner:
    def scan(self, targets, **kwargs):
        alive = [str(x) for x in (targets or [])]
        return {"success": True, "command": "httpx -silent ...", "alive": alive}


class FakeWhatwebScanner:
    def scan(self, target, **kwargs):
        return {
            "success": True,
            "command": f"whatweb {target} --log-json -",
            "scan_data": [{"target": target, "plugins": {"Country": {}, "IP": {}}}],
        }


class FakeNucleiScanner:
    def scan(self, target, **kwargs):
        return {"success": True, "command": f"nuclei -u {target} -jsonl", "findings": []}


class FakeGobusterScanner:
    def scan(self, target, **kwargs):
        return {"success": True, "command": f"gobuster dir -u {target} ...", "findings": []}


class FakeLLMIterative:
    def __init__(self):
        self.plan_calls = 0

    def tool_call(self, messages, tools, tool_choice=None, temperature=0.2):
        self.plan_calls += 1
        if self.plan_calls == 1:
            return (
                [
                    {
                        "name": "propose_actions",
                        "arguments": {
                            "actions": [
                                {
                                    "tool_name": "whatweb",
                                    "arguments": {"profile": "standard", "target": "http://localhost:19090"},
                                    "reasoning": "Validate stack signal on second discovered web target.",
                                    "hypothesis": "Secondary web service may expose different attack surface evidence.",
                                    "expected_evidence": "Technology fingerprint and headers from 19090 endpoint.",
                                    "priority": 5,
                                },
                                {
                                    "tool_name": "nuclei",
                                    "arguments": {"profile": "standard", "target": "http://localhost:19090"},
                                    "reasoning": "Run template checks on same target.",
                                    "hypothesis": "Nuclei may confirm misconfiguration signals on 19090.",
                                    "expected_evidence": "Template matches for known misconfigs.",
                                    "priority": 20,
                                },
                            ],
                            "stop": False,
                            "notes": "Initial expansion on uncovered target.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 10}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Sufficient signal."}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 6}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 12}},
        )


class FakeLLMNormalization:
    def __init__(self):
        self.plan_calls = 0

    def tool_call(self, messages, tools, tool_choice=None, temperature=0.2):
        self.plan_calls += 1
        if self.plan_calls == 1:
            return (
                [
                    {
                        "name": "propose_actions",
                        "arguments": {
                            "actions": [
                                {
                                    "tool_name": "nuclei",
                                    "arguments": {"profile": "totally-invalid", "target": "http://localhost:19090"},
                                    "reasoning": "Test normalization of action arguments.",
                                    "priority": 999,
                                }
                            ],
                            "stop": False,
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 8}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


def _build_scanners():
    return {
        "nmap": FakeNmapScanner(),
        "httpx": FakeHttpxScanner(),
        "whatweb": FakeWhatwebScanner(),
        "nuclei": FakeNucleiScanner(),
        "gobuster": FakeGobusterScanner(),
    }


class TestAIAuditOrchestrator(unittest.TestCase):
    def test_iterative_loop_executes_one_primary_action_per_cycle(self):
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=FakeLLMIterative())
        output = artifact_path("ai_audit_iterative_loop.json")
        report = orchestrator.run("localhost", output, llm_plan=True, max_actions=5, use_llm=True)

        ai = report.get("ai_audit", {})
        self.assertEqual(ai.get("planner_mode"), "iterative")
        actions = ai.get("actions", [])
        self.assertIsInstance(actions, list)
        self.assertEqual(len(actions), 1)
        if actions:
            self.assertEqual(actions[0].get("tool"), "whatweb")
            self.assertEqual(actions[0].get("priority"), 5)
            self.assertEqual(actions[0].get("target"), "http://localhost:19090")

        trace = ai.get("decision_trace", [])
        self.assertIsInstance(trace, list)
        self.assertGreaterEqual(len(trace), 2)
        if trace:
            first = trace[0]
            self.assertEqual(first.get("planner", {}).get("candidate_count"), 2)
            self.assertEqual(first.get("selected_action", {}).get("tool"), "whatweb")
            self.assertEqual(first.get("outcome", {}).get("status"), "success")

        replay = report.get("replay_trace", {})
        self.assertIsInstance(replay, dict)
        replay_file = replay.get("file")
        self.assertIsInstance(replay_file, str)
        if isinstance(replay_file, str):
            replay_path = Path(output).parent / replay_file
            self.assertTrue(replay_path.exists())
            replay_payload = json.loads(replay_path.read_text(encoding="utf-8"))
            self.assertIsInstance(replay_payload.get("decision_trace"), list)
            self.assertEqual(len(replay_payload.get("decision_trace", [])), len(trace))

    def test_action_normalization_clamps_priority_and_defaults_optional_fields(self):
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=FakeLLMNormalization())
        output = artifact_path("ai_audit_action_normalization.json")
        report = orchestrator.run("localhost", output, llm_plan=True, max_actions=3, use_llm=True)

        ai = report.get("ai_audit", {})
        actions = ai.get("actions", [])
        self.assertIsInstance(actions, list)
        self.assertEqual(len(actions), 1)
        if actions:
            action = actions[0]
            self.assertEqual(action.get("tool"), "nuclei")
            self.assertEqual(action.get("priority"), 100)
            self.assertEqual(action.get("profile"), "standard")
            self.assertEqual(action.get("hypothesis"), "")
            self.assertEqual(action.get("expected_evidence"), "")

    def test_progress_callback_includes_live_planner_decision_and_critique(self):
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=FakeLLMIterative())
        output = artifact_path("ai_audit_progress_stream.json")
        events = []

        def progress_cb(event, tool, message, agg):
            events.append((str(event), str(tool), str(message)))

        orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=5,
            use_llm=True,
            progress_cb=progress_cb,
        )

        event_names = [e[0] for e in events]
        self.assertIn("llm_start", event_names)
        self.assertIn("llm_plan", event_names)
        self.assertIn("llm_decision", event_names)
        self.assertIn("llm_critique", event_names)
        decision_msgs = [m for e, _, m in events if e == "llm_decision"]
        self.assertTrue(any("selected=whatweb" in m for m in decision_msgs))


if __name__ == "__main__":
    unittest.main()
