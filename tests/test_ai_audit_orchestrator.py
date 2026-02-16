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


class FakeNmapScannerWithTLS:
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
                                "port": 443,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "https",
                                "product": "nginx",
                                "version": "1.0",
                            }
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
        command = f"nuclei -u {target} -jsonl"
        rate_limit = kwargs.get("rate_limit")
        if rate_limit:
            command = f"{command} -rate-limit {int(rate_limit)}"
        return {"success": True, "command": command, "findings": []}


class FakeGobusterScanner:
    def scan(self, target, **kwargs):
        return {"success": True, "command": f"gobuster dir -u {target} ...", "findings": []}


class FakeFfufScanner:
    def scan(self, target, **kwargs):
        return {"success": True, "command": f"ffuf -u {target}/FUZZ ...", "findings": []}


class FakeSubfinderScanner:
    def scan(self, target, **kwargs):
        return {
            "success": True,
            "command": f"subfinder -d {target}",
            "hosts": ["app.example.com", "api.example.com", "cdn.example.com"],
        }


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


class FakeLLMStopWithAction:
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
                                    "reasoning": "Collect one final stack signal, then stop.",
                                    "priority": 5,
                                }
                            ],
                            "stop": True,
                            "notes": "Execute one action then stop.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 7}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 3}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 7}},
        )


class FakeLLMReplanOnCovered:
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
                                    "tool_name": "httpx",
                                    "arguments": {"profile": "standard", "target": "http://localhost:8080"},
                                    "reasoning": "Re-run httpx on primary target.",
                                    "priority": 5,
                                }
                            ],
                            "stop": False,
                            "notes": "First candidate may already be covered.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 9}},
            )
        return (
            [
                {
                    "name": "propose_actions",
                    "arguments": {
                        "actions": [
                            {
                                "tool_name": "whatweb",
                                "arguments": {"profile": "standard", "target": "http://localhost:19090"},
                                "reasoning": "Pivot to uncovered target after exclusion hint.",
                                "priority": 6,
                            }
                        ],
                        "stop": False,
                        "notes": "Second plan after exclusion list.",
                    },
                }
            ],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 7}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 9}},
        )


class FakeLLMSelectFfuf:
    def __init__(self):
        self.plan_calls = 0
        self.summary_calls = 0

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
                                    "tool_name": "ffuf",
                                    "arguments": {"profile": "standard", "target": "http://localhost:19090"},
                                    "reasoning": "Content discovery for uncovered paths.",
                                    "priority": 5,
                                }
                            ],
                            "stop": False,
                            "notes": "Run ffuf once.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 9}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Done."}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        self.summary_calls += 1
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeSslscanScanner:
    def __init__(self):
        self.calls = []

    def scan(self, target, port=None, **kwargs):
        self.calls.append((str(target), int(port or 0)))
        return {"success": True, "command": f"sslscan {target}:{int(port or 0)}", "scan_data": {}}


class FakeLLMRepeatSslscan:
    def __init__(self):
        self.plan_calls = 0

    def tool_call(self, messages, tools, tool_choice=None, temperature=0.2):
        self.plan_calls += 1
        return (
            [
                {
                    "name": "propose_actions",
                    "arguments": {
                        "actions": [
                            {
                                "tool_name": "sslscan",
                                "arguments": {"profile": "standard", "target": "localhost", "port": 443},
                                "reasoning": "Re-check TLS quickly.",
                                "priority": 5,
                            }
                        ],
                        "stop": False,
                        "notes": "Keep checking TLS.",
                    },
                }
            ],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 7}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeLLMRepeatNucleiTargets:
    def __init__(self):
        self.plan_calls = 0
        self._targets = [
            "http://localhost:8080",
            "http://localhost:9090",
            "http://localhost:19090",
            "http://localhost:4006",
        ]

    def tool_call(self, messages, tools, tool_choice=None, temperature=0.2):
        self.plan_calls += 1
        idx = (self.plan_calls - 1) % len(self._targets)
        target = self._targets[idx]
        return (
            [
                {
                    "name": "propose_actions",
                    "arguments": {
                        "actions": [
                            {
                                "tool_name": "nuclei",
                                "arguments": {"profile": "standard", "target": target},
                                "reasoning": "Repeat nuclei on another web target.",
                                "priority": 5,
                            }
                        ],
                        "stop": False,
                        "notes": "Keep running nuclei.",
                    },
                }
            ],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 6}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeLLMSelectSubfinder:
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
                                    "tool_name": "subfinder",
                                    "arguments": {"profile": "standard", "target": "example.com"},
                                    "reasoning": "Expand subdomain surface for validation.",
                                    "priority": 5,
                                }
                            ],
                            "stop": False,
                            "notes": "Run subfinder once.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 8}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Done."}}],
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
            self.assertIn("risk_class_delta", first.get("outcome", {}))

        replay = report.get("replay_trace", {})
        self.assertIsInstance(replay, dict)
        replay_file = replay.get("file")
        replay_md_file = replay.get("markdown_file")
        self.assertIsInstance(replay_file, str)
        self.assertIsInstance(replay_md_file, str)
        if isinstance(replay_file, str):
            replay_path = Path(output).parent / replay_file
            self.assertTrue(replay_path.exists())
            replay_payload = json.loads(replay_path.read_text(encoding="utf-8"))
            self.assertIsInstance(replay_payload.get("decision_trace"), list)
            self.assertEqual(len(replay_payload.get("decision_trace", [])), len(trace))
        if isinstance(replay_md_file, str):
            replay_md_path = Path(output).parent / replay_md_file
            self.assertTrue(replay_md_path.exists())
            replay_md = replay_md_path.read_text(encoding="utf-8")
            self.assertIn("# Audit Replay Trace", replay_md)
            self.assertIn("## Decision Steps", replay_md)

        llm_trace = report.get("llm_reasoning_trace", {})
        self.assertIsInstance(llm_trace, dict)
        trace_json = llm_trace.get("json_file")
        trace_md = llm_trace.get("markdown_file")
        self.assertIsInstance(trace_json, str)
        self.assertIsInstance(trace_md, str)
        if isinstance(trace_json, str):
            self.assertTrue((Path(output).parent / trace_json).exists())
        if isinstance(trace_md, str):
            self.assertTrue((Path(output).parent / trace_md).exists())
        self.assertIn("finding_metrics", report)
        self.assertIn("duplicate_rate", report.get("finding_metrics", {}))

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

    def test_stop_true_with_candidates_executes_one_action_then_stops(self):
        llm = FakeLLMStopWithAction()
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=llm)
        output = artifact_path("ai_audit_stop_with_action.json")
        report = orchestrator.run("localhost", output, llm_plan=True, max_actions=5, use_llm=True)

        ai = report.get("ai_audit", {})
        actions = ai.get("actions", [])
        self.assertEqual(len(actions), 1)
        if actions:
            self.assertEqual(actions[0].get("tool"), "whatweb")

        trace = ai.get("decision_trace", [])
        self.assertEqual(len(trace), 1)
        if trace:
            self.assertEqual(trace[0].get("decision", {}).get("result"), "executed")
            self.assertTrue(trace[0].get("decision", {}).get("stop_after_execution"))

        self.assertEqual(llm.plan_calls, 1)

    def test_replan_once_when_all_candidates_are_already_covered(self):
        llm = FakeLLMReplanOnCovered()
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=llm)
        output = artifact_path("ai_audit_replan_on_covered.json")
        report = orchestrator.run("localhost", output, llm_plan=True, max_actions=1, use_llm=True)

        ai = report.get("ai_audit", {})
        actions = ai.get("actions", [])
        self.assertEqual(len(actions), 1)
        if actions:
            self.assertEqual(actions[0].get("tool"), "whatweb")
            self.assertEqual(actions[0].get("target"), "http://localhost:19090")

        trace = ai.get("decision_trace", [])
        self.assertEqual(len(trace), 1)
        if trace:
            self.assertIn("replan", trace[0])
            self.assertTrue(trace[0].get("replan", {}).get("attempted"))
            self.assertEqual(trace[0].get("decision", {}).get("result"), "executed")

        self.assertEqual(llm.plan_calls, 2)

    def test_ffuf_summary_note_does_not_break_llm_summary(self):
        scanners = _build_scanners()
        scanners["ffuf"] = FakeFfufScanner()
        llm = FakeLLMSelectFfuf()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=llm)
        # ffuf has enabled_default=False in tool specs; force-enable in this test.
        orchestrator._tool_enabled = lambda _tool, default=True: True
        output = artifact_path("ai_audit_ffuf_summary_note.json")
        report = orchestrator.run("localhost", output, llm_plan=True, max_actions=2, use_llm=True)

        self.assertIsInstance(report.get("summary"), dict)
        self.assertGreaterEqual(llm.summary_calls, 1)
        notes = report.get("summary_notes", [])
        self.assertTrue(any("agentic ffuf action(s) ran and found" in str(n) for n in notes))

    def test_agentic_nuclei_honors_configured_rate_limit(self):
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=FakeLLMNormalization())
        output = artifact_path("ai_audit_nuclei_rate_from_config.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
            nuclei_rate_limit=10000,
        )

        agentic_nuclei = [
            entry
            for entry in (report.get("results") or [])
            if isinstance(entry, dict)
            and entry.get("tool") == "nuclei"
            and entry.get("phase") == "agentic"
            and entry.get("target") == "http://localhost:19090"
        ]
        self.assertTrue(agentic_nuclei)
        command = str(agentic_nuclei[0].get("command") or "")
        self.assertIn("-rate-limit 10000", command)

    def test_repeat_policy_caps_low_signal_sslscan_repeats(self):
        scanners = _build_scanners()
        sslscan = FakeSslscanScanner()
        scanners["nmap"] = FakeNmapScannerWithTLS()
        scanners["sslscan"] = sslscan
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMRepeatSslscan())
        output = artifact_path("ai_audit_repeat_policy_sslscan.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=3,
            use_llm=True,
            compliance_profile="pci",
        )

        self.assertGreaterEqual(len(sslscan.calls), 1)
        agentic_sslscan_actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "sslscan" and a.get("phase") == "agentic"
        ]
        self.assertEqual(len(agentic_sslscan_actions), 1)
        trace = report.get("ai_audit", {}).get("decision_trace", [])
        self.assertIsInstance(trace, list)
        self.assertGreaterEqual(len(trace), 2)
        if isinstance(trace, list) and len(trace) >= 2:
            second = trace[1]
            self.assertEqual(second.get("decision", {}).get("reason"), "all_candidates_blocked_repeat_policy")
            self.assertIn("repeat_filtered", second)

    def test_repeat_policy_caps_agentic_nuclei_after_broad_baseline(self):
        scanners = _build_scanners()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMRepeatNucleiTargets())
        output = artifact_path("ai_audit_repeat_policy_nuclei_cap.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=5,
            use_llm=True,
            compliance_profile="soc2",
        )

        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "nuclei" and a.get("phase") == "agentic"
        ]
        self.assertLessEqual(len(actions), 2)

    def test_agentic_subfinder_promotions_are_validated_with_httpx(self):
        scanners = _build_scanners()
        scanners["subfinder"] = FakeSubfinderScanner()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectSubfinder())
        orchestrator._tool_enabled = lambda _tool, default=True: True
        orchestrator._promote_subfinder_hosts = lambda _scan_host, _hosts: {
            "urls": [
                "https://app.example.com",
                "http://app.example.com",
                "https://api.example.com",
            ],
            "stats": {
                "discovered": 3,
                "in_scope": 3,
                "resolved": 3,
                "promoted_hosts": 2,
                "promoted_urls": 3,
                "resolve_validation": True,
            },
        }
        output = artifact_path("ai_audit_agentic_subfinder_validation.json")
        report = orchestrator.run(
            "example.com",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
        )

        validation_entries = [
            r
            for r in (report.get("results") or [])
            if isinstance(r, dict)
            and r.get("tool") == "httpx"
            and r.get("phase") == "agentic"
            and r.get("target_scope") == "subfinder_promotion_validation"
        ]
        self.assertTrue(validation_entries)
        subfinder_actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "subfinder" and a.get("phase") == "agentic"
        ]
        self.assertTrue(subfinder_actions)
        subfinder_result = None
        for r in (report.get("results") or []):
            if isinstance(r, dict) and r.get("tool") == "subfinder" and r.get("phase") == "agentic":
                subfinder_result = r
                break
        self.assertIsNotNone(subfinder_result)
        if isinstance(subfinder_result, dict):
            data = subfinder_result.get("data", {})
            self.assertIn("validated_urls", data)
            self.assertIsInstance(data.get("validated_urls"), list)
        notes = report.get("summary_notes", [])
        self.assertTrue(any("validated URLs" in str(n) for n in notes))


if __name__ == "__main__":
    unittest.main()
