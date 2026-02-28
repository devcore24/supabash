import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

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


class FakeNucleiScannerWithFindings:
    def scan(self, target, **kwargs):
        command = f"nuclei -u {target} -jsonl"
        rate_limit = kwargs.get("rate_limit")
        if rate_limit:
            command = f"{command} -rate-limit {int(rate_limit)}"
        target_txt = str(target or "").rstrip("/")
        return {
            "success": True,
            "command": command,
            "findings": [
                {
                    "id": "http-missing-security-headers",
                    "name": "HTTP Missing Security Headers",
                    "severity": "info",
                    "matched_at": f"{target_txt}/",
                    "type": "http",
                }
            ],
        }


class FakeNucleiScannerWithHighFindings:
    def scan(self, target, **kwargs):
        command = f"nuclei -u {target} -jsonl"
        rate_limit = kwargs.get("rate_limit")
        if rate_limit:
            command = f"{command} -rate-limit {int(rate_limit)}"
        target_txt = str(target or "").rstrip("/")
        target_slug = (
            target_txt.replace("://", "-")
            .replace("/", "-")
            .replace(":", "-")
            .replace(".", "-")
        )
        return {
            "success": True,
            "command": command,
            "findings": [
                {
                    "id": f"prometheus-unauthenticated-{target_slug}",
                    "name": f"Prometheus Monitoring System - Unauthenticated ({target_slug})",
                    "severity": "high",
                    "matched_at": f"{target_txt}/api/v1/status/config",
                    "type": "http",
                }
            ],
        }


class FakeGobusterScanner:
    def scan(self, target, **kwargs):
        return {"success": True, "command": f"gobuster dir -u {target} ...", "findings": []}


class FakeNmapScannerSingleWebPort:
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
                            }
                        ],
                    }
                ]
            },
        }


class FakeNmapScannerSupabaseOnly:
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
                                "port": 4001,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "postgrest",
                                "version": "11",
                            }
                        ],
                    }
                ]
            },
        }


class FakeNmapScannerPrometheusAndTls9433:
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
                                "port": 9090,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "prometheus",
                                "version": "2.0",
                            },
                            {
                                "port": 9433,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "https",
                                "product": "custom-ui",
                                "version": "1.0",
                            },
                        ],
                    }
                ]
            },
        }


class FakeKatanaQueryScanner:
    def crawl(self, target, **kwargs):
        base = str(target).rstrip("/")
        urls = [f"{base}/search?query=test"]
        return {"success": True, "command": f"katana -u {target}", "urls": urls, "findings": urls}


class FakeSqlmapCaptureScanner:
    def __init__(self):
        self.calls = []

    def scan(self, target, **kwargs):
        self.calls.append(str(target))
        return {"success": True, "command": f"sqlmap -u {target}", "findings": []}


class FakeGobusterWildcardScanner:
    def __init__(self):
        self.calls = []

    def scan(self, target, **kwargs):
        self.calls.append(str(target))
        return {
            "success": False,
            "command": f"gobuster dir -u {target} ...",
            "error": (
                "Error: the server returns a status code that matches the provided options "
                "for non existing urls. To continue please exclude the status code "
                "or use the --wildcard switch."
            ),
        }


class FakeFfufScanner:
    def scan(self, target, **kwargs):
        return {"success": True, "command": f"ffuf -u {target}/FUZZ ...", "findings": []}


class FakeFfufRecordingScanner:
    def __init__(self):
        self.calls = []

    def scan(self, target, **kwargs):
        self.calls.append(str(target))
        return {
            "success": True,
            "command": f"ffuf -u {target}/FUZZ ...",
            "findings": ["/admin [Status: 200, Size: 1234]"],
        }


class FakeSubfinderScanner:
    def scan(self, target, **kwargs):
        return {
            "success": True,
            "command": f"subfinder -d {target}",
            "hosts": ["app.example.com", "api.example.com", "cdn.example.com"],
        }


class FakeBrowserUseScanner:
    def __init__(self):
        self.calls = []

    def is_available(self, command_override=None):
        return True

    def scan(self, target, **kwargs):
        self.calls.append({"target": str(target), "kwargs": dict(kwargs)})
        return {
            "success": True,
            "command": f"browser-use run 'scan {target}' --max-steps 12",
            "urls": [f"{str(target).rstrip('/')}/login"],
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Potential authentication bypass signal",
                    "evidence": f"{target}/login accepted weak session workflow",
                    "type": "browser_observation",
                }
            ],
        }


class FakeBrowserUseEnvCaptureScanner(FakeBrowserUseScanner):
    def scan(self, target, **kwargs):
        env_seen = os.getenv("BROWSER_USE_API_KEY")
        result = super().scan(target, **kwargs)
        if self.calls:
            self.calls[-1]["env_browser_use_api_key"] = env_seen
        return result


class FakeBrowserUseFallbackScanner:
    def __init__(self):
        self.calls = []

    def is_available(self, command_override=None):
        return True

    def scan(self, target, **kwargs):
        self.calls.append({"target": str(target), "kwargs": dict(kwargs)})
        return {
            "success": True,
            "command": f"browser-use run 'scan {target}' --max-steps 8",
            "urls": [
                f"{str(target).rstrip('/')}/login",
                f"{str(target).rstrip('/')}/admin",
            ],
            "findings": [],
            "observation": {
                "done": False,
                "steps": 0,
                "data_success": True,
                "result": "",
                "urls_count": 2,
                "findings_count": 0,
                "evidence_score": 2,
                "fallback_mode": "deterministic_probe",
                "fallback_steps": 10,
                "fallback_urls_count": 2,
                "fallback_findings_count": 0,
                "focus_urls_count": 2,
                "focus_hits": 0,
                "fallback_confidence": "low",
            },
            "completed": False,
        }


class FakeBrowserUseCorrelationScanner:
    def __init__(self):
        self.calls = []

    def is_available(self, command_override=None):
        return True

    def scan(self, target, **kwargs):
        self.calls.append({"target": str(target), "kwargs": dict(kwargs)})
        base = str(target).rstrip("/")
        return {
            "success": True,
            "command": f"browser-use run 'scan {target}' --max-steps 8",
            "urls": [f"{base}/api/v1/status/config"],
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Unauthenticated configuration exposure verified in browser workflow",
                    "evidence": (
                        f"{base}/api/v1/status/config returned configuration-like content "
                        "without authentication workflow."
                    ),
                    "type": "browser_observation",
                    "confidence": "high",
                }
            ],
            "completed": True,
            "observation": {
                "done": True,
                "steps": 3,
                "focus_hits": 1,
                "focused_endpoint_artifacts": 1,
            },
        }


class FakeBrowserUseTargetOnlyScanner:
    def __init__(self):
        self.calls = []

    def is_available(self, command_override=None):
        return True

    def scan(self, target, **kwargs):
        self.calls.append({"target": str(target), "kwargs": dict(kwargs)})
        return {
            "success": True,
            "command": f"browser-use run 'scan {target}' --max-steps 6",
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Browser-driven security signal",
                    "evidence": "HTTP 200 OK (Unauthenticated)",
                    "type": "browser_observation",
                    "confidence": "high",
                }
            ],
            "completed": True,
            "observation": {
                "done": True,
                "steps": 2,
                "focus_hits": 1,
                "focused_endpoint_artifacts": 1,
            },
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


class FakeLLMSelectBrowserUse:
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
                                    "tool_name": "browser_use",
                                    "arguments": {
                                        "profile": "standard",
                                        "target": "http://localhost:9090",
                                        "max_steps": 12,
                                    },
                                    "reasoning": "Use browser-driven validation on exposed web surface.",
                                    "hypothesis": "Interactive workflow may expose weak auth behavior.",
                                    "expected_evidence": "Browser-observed auth/session weakness on login path.",
                                    "priority": 3,
                                }
                            ],
                            "stop": False,
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-browser-use-planner", "usage": {"total_tokens": 8}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True}}],
            {"provider": "fake", "model": "fake-browser-use-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeLLMRepeatBrowserUse:
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
                                "tool_name": "browser_use",
                                "arguments": {
                                    "profile": "standard",
                                    "target": "http://localhost:9090",
                                    "max_steps": 8,
                                },
                                "reasoning": "Repeat browser validation on same target.",
                                "priority": 5,
                            }
                        ],
                        "stop": False,
                        "notes": "Keep testing same browser target.",
                    },
                }
            ],
            {"provider": "fake", "model": "fake-browser-use-repeat", "usage": {"total_tokens": 7}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeLLMSelectBrowserUse8080:
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
                                    "tool_name": "browser_use",
                                    "arguments": {
                                        "profile": "standard",
                                        "target": "http://localhost:8080",
                                        "max_steps": 10,
                                    },
                                    "reasoning": "Corroborate high-risk unauthenticated config signal on same host:port.",
                                    "hypothesis": "Agentic browser evidence should close matching high-risk cluster.",
                                    "expected_evidence": "Endpoint evidence with unauthenticated config disclosure language.",
                                    "priority": 2,
                                }
                            ],
                            "stop": False,
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-browser-use-planner", "usage": {"total_tokens": 8}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True}}],
            {"provider": "fake", "model": "fake-browser-use-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeLLMSelectCoveredHttpx4001:
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
                                    "arguments": {"profile": "soc2", "target": "http://localhost:4001"},
                                    "reasoning": "Repeat a simple host-level status check on the Supabase endpoint.",
                                    "hypothesis": "The host root may be enough to resolve the remaining exposure.",
                                    "expected_evidence": "HTTP response details from the already-known host root.",
                                    "priority": 5,
                                }
                            ],
                            "stop": False,
                            "notes": "Start from the known host root.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-covered-httpx-planner", "usage": {"total_tokens": 8}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Done."}}],
            {"provider": "fake", "model": "fake-covered-httpx-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 8}},
        )


class FakeLLMCloseThenProbe9433:
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
                                    "tool_name": "browser_use",
                                    "arguments": {
                                        "profile": "soc2",
                                        "target": "http://localhost:9090/api/v1/status/config",
                                    },
                                    "reasoning": "Close the known Prometheus auth gap with direct browser validation.",
                                    "priority": 1,
                                }
                            ],
                            "stop": False,
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-close-then-probe", "usage": {"total_tokens": 8}},
            )
        if self.plan_calls == 2:
            return (
                [
                    {
                        "name": "propose_actions",
                        "arguments": {
                            "actions": [
                                {
                                    "tool_name": "nuclei",
                                    "arguments": {"profile": "soc2", "target": "http://localhost:9433"},
                                    "reasoning": "Probe another service after closure.",
                                    "priority": 5,
                                }
                            ],
                            "stop": False,
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-close-then-probe", "usage": {"total_tokens": 7}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True}}],
            {"provider": "fake", "model": "fake-close-then-probe", "usage": {"total_tokens": 4}},
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


class FakeLLMRepeatSameNucleiTarget:
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
                                "tool_name": "nuclei",
                                "arguments": {
                                    "profile": "soc2",
                                    "target": "http://localhost:9090/api/v1/status/config",
                                },
                                "reasoning": "Re-validate unresolved high-risk Prometheus exposure.",
                                "priority": 1,
                            }
                        ],
                        "stop": False,
                        "notes": "Keep checking unresolved high-risk cluster.",
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


class FakeLLMEndpointNuclei:
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
                                    "arguments": {
                                        "profile": "soc2",
                                        "target": "http://localhost:9090/api/v1/status/config",
                                    },
                                    "reasoning": "Validate a high-risk endpoint-level exposure.",
                                    "priority": 1,
                                }
                            ],
                            "stop": False,
                            "notes": "Run targeted nuclei on a specific exposed endpoint.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 6}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Done."}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 3}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 7}},
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


class FakeLLMSelectGobusterWildcardTarget:
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
                                    "tool_name": "gobuster",
                                    "arguments": {
                                        "profile": "soc2",
                                        "target": "http://localhost:9090/api/v1/status/config",
                                    },
                                    "reasoning": "Enumerate hidden paths on high-risk target.",
                                    "priority": 3,
                                }
                            ],
                            "stop": False,
                            "notes": "Try gobuster follow-up on exposed web surface.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 7}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Done."}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 7}},
        )


class FakeLLMSelectBlockedSqlmap:
    def __init__(self):
        self.plan_calls = 0

    def tool_call(self, messages, tools, tool_choice=None, temperature=0.2):
        self.plan_calls += 1
        if self.plan_calls in (1, 2):
            return (
                [
                    {
                        "name": "propose_actions",
                        "arguments": {
                            "actions": [
                                {
                                    "tool_name": "sqlmap",
                                    "arguments": {
                                        "profile": "soc2",
                                        "target": "http://localhost:8080/search?query=test",
                                    },
                                    "reasoning": "Validate SQL injection on discovered parameterized endpoint.",
                                    "priority": 5,
                                }
                            ],
                            "stop": False,
                            "notes": "Run sqlmap on discovered query endpoint.",
                        },
                    }
                ],
                {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 7}},
            )
        return (
            [{"name": "propose_actions", "arguments": {"actions": [], "stop": True, "notes": "Done."}}],
            {"provider": "fake", "model": "fake-planner", "usage": {"total_tokens": 4}},
        )

    def chat_with_meta(self, messages, temperature=0.2):
        return (
            json.dumps({"summary": "Synthetic summary.", "findings": []}),
            {"provider": "fake", "model": "fake-summary", "usage": {"total_tokens": 7}},
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

    def test_url_target_scope_does_not_merge_unrelated_nmap_web_ports(self):
        orchestrator = AIAuditOrchestrator(scanners=_build_scanners(), llm_client=FakeLLMStopWithAction())
        output = artifact_path("ai_audit_url_scope_no_nmap_merge.json")
        report = orchestrator.run(
            "http://127.0.0.1:3003/WebGoat",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
        )

        web_targets = report.get("web_targets") if isinstance(report.get("web_targets"), list) else []
        self.assertIn("http://127.0.0.1:3003/WebGoat", web_targets)
        self.assertNotIn("http://localhost:9090", web_targets)
        self.assertNotIn("http://localhost:8080", web_targets)

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

    def test_agentic_sqlmap_nonviable_target_is_not_retried(self):
        sqlmap = FakeSqlmapCaptureScanner()
        scanners = {
            "nmap": FakeNmapScannerSingleWebPort(),
            "httpx": FakeHttpxScanner(),
            "whatweb": FakeWhatwebScanner(),
            "nuclei": FakeNucleiScanner(),
            "gobuster": FakeGobusterScanner(),
            "katana": FakeKatanaQueryScanner(),
            "sqlmap": sqlmap,
        }
        llm = FakeLLMSelectBlockedSqlmap()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=llm)
        output = artifact_path("ai_audit_sqlmap_nonviable_not_retried.json")
        with patch.object(AIAuditOrchestrator, "_http_probe_status", return_value=(404, "", None)):
            report = orchestrator.run(
                "localhost",
                output,
                llm_plan=True,
                max_actions=2,
                use_llm=True,
                compliance_profile="soc2",
            )

        self.assertEqual(sqlmap.calls, [])
        agentic_sqlmap_actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "sqlmap" and a.get("phase") == "agentic"
        ]
        self.assertEqual(len(agentic_sqlmap_actions), 1)
        if agentic_sqlmap_actions:
            self.assertTrue(bool(agentic_sqlmap_actions[0].get("skipped")))
            self.assertIn(
                "preflight blocked non-viable url",
                str(agentic_sqlmap_actions[0].get("reason") or "").strip().lower(),
            )
        self.assertGreaterEqual(int(llm.plan_calls), 2)

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

    def test_coverage_debt_pivot_injects_non_nuclei_action_after_repeat_block(self):
        scanners = _build_scanners()
        scanners["nuclei"] = FakeNucleiScannerWithHighFindings()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMRepeatSameNucleiTarget())
        output = artifact_path("ai_audit_coverage_debt_pivot.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=3,
            use_llm=True,
            compliance_profile="soc2",
        )

        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("phase") == "agentic"
        ]
        self.assertGreaterEqual(len(actions), 1)

        trace = report.get("ai_audit", {}).get("decision_trace", [])
        self.assertIsInstance(trace, list)
        has_pivot = any(
            isinstance(step, dict) and isinstance(step.get("coverage_debt_pivot"), dict)
            for step in trace
        )
        has_unresolved_stop = any(
            isinstance(step, dict)
            and isinstance(step.get("decision"), dict)
            and str(step.get("decision", {}).get("reason") or "").strip() == "unresolved_high_risk_no_actionable_candidates"
            for step in trace
        )
        open_high_after = int(report.get("finding_cluster_overview", {}).get("open_high_risk_cluster_count", 0))
        self.assertTrue(has_pivot or has_unresolved_stop or open_high_after == 0)

        summary_notes = report.get("summary_notes", [])
        if has_pivot:
            self.assertTrue(any("Coverage-debt fallback pivot used" in str(n) for n in summary_notes))
        elif open_high_after > 0:
            self.assertTrue(any("Unresolved high-risk clusters remain after agentic phase" in str(n) for n in summary_notes))

    def test_agentic_delta_includes_phase_scoped_findings(self):
        scanners = _build_scanners()
        scanners["nuclei"] = FakeNucleiScannerWithFindings()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMRepeatNucleiTargets())
        output = artifact_path("ai_audit_agentic_phase_delta.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
        )

        delta = report.get("agentic_delta", {})
        self.assertIsInstance(delta, dict)
        self.assertGreater(int(delta.get("agentic_total_findings", 0) or 0), 0)
        self.assertGreater(int(delta.get("agentic_unique_findings", 0) or 0), 0)
        self.assertIn("agentic_duplicate_only_findings", delta)

    def test_endpoint_level_web_target_is_not_skipped_when_host_port_is_allowed(self):
        scanners = _build_scanners()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMEndpointNuclei())
        output = artifact_path("ai_audit_endpoint_level_target_allowed.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
        )

        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "nuclei" and a.get("phase") == "agentic"
        ]
        self.assertEqual(len(actions), 1)
        if actions:
            self.assertEqual(actions[0].get("target"), "http://localhost:9090/api/v1/status/config")
        trace = report.get("ai_audit", {}).get("decision_trace", [])
        self.assertIsInstance(trace, list)
        self.assertTrue(any((t.get("decision") or {}).get("result") == "executed" for t in trace if isinstance(t, dict)))

    def test_coverage_debt_injects_path_preserving_httpx_action_for_unresolved_rest_api_cluster(self):
        scanners = {
            "nmap": FakeNmapScannerSupabaseOnly(),
            "httpx": FakeHttpxScanner(),
            "whatweb": FakeWhatwebScanner(),
            "nuclei": FakeNucleiScanner(),
            "gobuster": FakeGobusterScanner(),
            "supabase_audit": SimpleNamespace(
                scan=lambda target, **kwargs: {
                    "success": True,
                    "command": f"supabase_audit {target}",
                    "exposures": [
                        {
                            "type": "rls_misconfig",
                            "url": "http://localhost:4001/rest/v1/",
                            "status": 200,
                        }
                    ],
                }
            ),
        }
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectCoveredHttpx4001())
        orchestrator._run_readiness_probe = lambda **kwargs: {"success": True, "findings": []}
        output = artifact_path("ai_audit_coverage_debt_rest_path.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
        )

        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("phase") == "agentic"
        ]
        self.assertEqual(len(actions), 1)
        if actions:
            self.assertEqual(actions[0].get("tool"), "httpx")
            self.assertEqual(actions[0].get("target"), "http://localhost:4001/rest/v1/")

        trace = report.get("ai_audit", {}).get("decision_trace", [])
        self.assertIsInstance(trace, list)
        self.assertTrue(
            any(
                isinstance(step, dict)
                and isinstance(step.get("coverage_debt_pivot"), dict)
                and any(
                    str((candidate or {}).get("target") or "").strip() == "http://localhost:4001/rest/v1/"
                    for candidate in (step.get("coverage_debt_pivot", {}).get("injected") or [])
                    if isinstance(candidate, dict)
                )
                for step in trace
            )
        )

    def test_gobuster_wildcard_target_pivots_to_ffuf_without_repeating_gobuster(self):
        scanners = _build_scanners()
        gobuster = FakeGobusterWildcardScanner()
        ffuf = FakeFfufRecordingScanner()
        scanners["gobuster"] = gobuster
        scanners["ffuf"] = ffuf
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectGobusterWildcardTarget())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "ffuf" else original_tool_enabled(tool, default)
        )
        output = artifact_path("ai_audit_gobuster_wildcard_pivot.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
        )

        self.assertTrue(any("localhost:9090" in call for call in gobuster.calls))
        gobuster_actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "gobuster" and a.get("phase") == "agentic"
        ]
        self.assertTrue(gobuster_actions)
        if gobuster_actions:
            self.assertTrue(bool(gobuster_actions[0].get("skipped")))
            self.assertIn("wildcard", str(gobuster_actions[0].get("reason") or "").lower())

        ffuf_fallback_entries = [
            r
            for r in (report.get("results") or [])
            if isinstance(r, dict)
            and r.get("tool") == "ffuf"
            and r.get("phase") == "agentic"
            and r.get("fallback_for") == "gobuster"
        ]
        self.assertTrue(ffuf_fallback_entries)
        self.assertTrue(any(bool(r.get("success")) for r in ffuf_fallback_entries))

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

    def test_agentic_browser_use_executes_when_enabled(self):
        scanners = _build_scanners()
        browser = FakeBrowserUseScanner()
        scanners["browser_use"] = browser
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        output = artifact_path("ai_audit_browser_use_enabled.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        self.assertTrue(browser.calls)
        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "browser_use" and a.get("phase") == "agentic"
        ]
        self.assertTrue(actions)
        browser_findings = [
            f
            for f in (report.get("findings") or [])
            if isinstance(f, dict) and str(f.get("tool") or "").strip().lower() == "browser_use"
        ]
        self.assertTrue(browser_findings)
        first_call = browser.calls[0]
        task = str(first_call.get("kwargs", {}).get("task") or "")
        self.assertIn("Target URL:", task)
        self.assertIn("Execution guidance:", task)
        self.assertIn("Output requirements:", task)
        self.assertEqual(first_call.get("kwargs", {}).get("require_done"), True)
        self.assertEqual(first_call.get("kwargs", {}).get("min_steps_success"), 1)
        self.assertEqual(first_call.get("kwargs", {}).get("allow_deterministic_fallback"), True)
        self.assertEqual(first_call.get("kwargs", {}).get("deterministic_max_paths"), 8)

    def test_browser_use_fallback_no_cluster_closure_blocks_repeat_on_same_target(self):
        scanners = _build_scanners()
        browser = FakeBrowserUseFallbackScanner()
        scanners["browser_use"] = browser
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMRepeatBrowserUse())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        output = artifact_path("ai_audit_browser_use_fallback_repeat_block.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        self.assertEqual(len(browser.calls), 1)
        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "browser_use" and a.get("phase") == "agentic"
        ]
        self.assertEqual(len(actions), 1)
        trace = report.get("ai_audit", {}).get("decision_trace", [])
        filtered_reasons = []
        for t in trace:
            if not isinstance(t, dict):
                continue
            rep = t.get("repeat_filtered") if isinstance(t.get("repeat_filtered"), dict) else {}
            for c in rep.get("candidates", []) or []:
                if isinstance(c, dict):
                    filtered_reasons.append(str(c.get("reason") or ""))
        replan_reasons = [
            str((t.get("replan") or {}).get("reason") or "")
            for t in trace
            if isinstance(t, dict) and isinstance(t.get("replan"), dict)
        ]
        self.assertTrue(
            ("browser_use_fallback_no_cluster_closure" in filtered_reasons)
            or ("all_candidates_already_covered" in replan_reasons)
        )

    def test_high_risk_cluster_closes_when_agentic_evidence_matches_risk_class_and_host(self):
        scanners = _build_scanners()
        scanners["nuclei"] = FakeNucleiScannerWithHighFindings()
        scanners["browser_use"] = FakeBrowserUseCorrelationScanner()
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse8080())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        output = artifact_path("ai_audit_browser_use_cluster_closure.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        unresolved = report.get("unresolved_high_risk_clusters", [])
        self.assertIsInstance(unresolved, list)
        self.assertEqual(len(unresolved), 0)
        cluster_overview = report.get("finding_cluster_overview", {})
        self.assertEqual(int(cluster_overview.get("open_high_risk_cluster_count", 0)), 0)

    def test_endpoint_target_browser_observation_closes_matching_cluster_via_target_field(self):
        scanners = {
            "nmap": FakeNmapScannerSingleWebPort(),
            "httpx": FakeHttpxScanner(),
            "whatweb": FakeWhatwebScanner(),
            "nuclei": FakeNucleiScanner(),
            "gobuster": FakeGobusterScanner(),
            "browser_use": FakeBrowserUseTargetOnlyScanner(),
        }
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse8080())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        orchestrator._run_readiness_probe = lambda **kwargs: {
            "success": True,
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus config endpoint accessible without authentication",
                    "evidence": "http://localhost:8080/api/v1/status/config (HTTP 200)",
                    "type": "prometheus_config_exposure",
                }
            ],
        }
        output = artifact_path("ai_audit_browser_use_endpoint_target_closure.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=1,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        unresolved = report.get("unresolved_high_risk_clusters", [])
        self.assertIsInstance(unresolved, list)
        self.assertEqual(len(unresolved), 0)
        cluster_overview = report.get("finding_cluster_overview", {})
        self.assertEqual(int(cluster_overview.get("open_high_risk_cluster_count", 0)), 0)

    def test_post_closure_low_value_followups_are_stopped_before_execution(self):
        scanners = {
            "nmap": FakeNmapScannerPrometheusAndTls9433(),
            "httpx": FakeHttpxScanner(),
            "whatweb": FakeWhatwebScanner(),
            "nuclei": FakeNucleiScanner(),
            "gobuster": FakeGobusterScanner(),
            "browser_use": FakeBrowserUseTargetOnlyScanner(),
            "sslscan": FakeSslscanScanner(),
        }
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMCloseThenProbe9433())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        orchestrator._run_readiness_probe = lambda **kwargs: {
            "success": True,
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Prometheus config endpoint accessible without authentication",
                    "evidence": "http://localhost:9090/api/v1/status/config (HTTP 200)",
                    "type": "prometheus_config_exposure",
                }
            ],
        }
        output = artifact_path("ai_audit_post_closure_stop.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=3,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("phase") == "agentic"
        ]
        self.assertEqual(len(actions), 1)
        if actions:
            self.assertEqual(actions[0].get("tool"), "browser_use")
        trace = report.get("ai_audit", {}).get("decision_trace", [])
        self.assertTrue(
            any(
                isinstance(step, dict)
                and str((step.get("decision") or {}).get("reason") or "").strip() == "post_closure_low_marginal_signal"
                for step in trace
            )
        )

    def test_agentic_browser_use_skipped_when_disabled(self):
        scanners = _build_scanners()
        browser = FakeBrowserUseScanner()
        scanners["browser_use"] = browser
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        output = artifact_path("ai_audit_browser_use_disabled.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=False,
        )

        self.assertFalse(browser.calls)
        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "browser_use" and a.get("phase") == "agentic"
        ]
        self.assertFalse(actions)

    def test_agentic_browser_use_uses_configured_session_profile_and_auth_context(self):
        scanners = _build_scanners()
        browser = FakeBrowserUseScanner()
        scanners["browser_use"] = browser
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        original_tool_config = orchestrator._tool_config

        def _tool_config_override(name):
            if str(name or "").strip().lower() == "browser_use":
                return {
                    "enabled": True,
                    "timeout_seconds": 900,
                    "max_steps": 25,
                    "headless": True,
                    "session": "supabash-session",
                    "profile": "supabash-profile",
                    "auth": {
                        "enabled": True,
                        "login_url": "http://localhost:9090/login",
                        "notes": "Use approved QA account only.",
                    },
                }
            return original_tool_config(name)

        orchestrator._tool_config = _tool_config_override
        output = artifact_path("ai_audit_browser_use_auth_context.json")
        report = orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        self.assertTrue(browser.calls)
        call = browser.calls[0]
        kwargs = call.get("kwargs", {})
        self.assertEqual(kwargs.get("session"), "supabash-session")
        self.assertEqual(kwargs.get("profile"), "supabash-profile")
        task = str(kwargs.get("task") or "")
        self.assertIn("Authentication context is configured for this run.", task)
        self.assertIn("Preferred login URL: http://localhost:9090/login", task)
        self.assertIn("Auth notes: Use approved QA account only.", task)
        actions = [
            a
            for a in (report.get("ai_audit", {}).get("actions") or [])
            if isinstance(a, dict) and a.get("tool") == "browser_use" and a.get("phase") == "agentic"
        ]
        self.assertTrue(actions)

    def test_agentic_browser_use_auto_session_when_not_configured(self):
        scanners = _build_scanners()
        browser = FakeBrowserUseScanner()
        scanners["browser_use"] = browser
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        output = artifact_path("ai_audit_browser_use_auto_session.json")
        orchestrator.run(
            "localhost",
            output,
            llm_plan=True,
            max_actions=2,
            use_llm=True,
            compliance_profile="soc2",
            run_browser_use=True,
        )

        self.assertTrue(browser.calls)
        call = browser.calls[0]
        kwargs = call.get("kwargs", {})
        session_name = str(kwargs.get("session") or "")
        self.assertTrue(session_name.startswith("supabash-"))

    def test_agentic_browser_use_exports_configured_api_key_and_restores_env(self):
        scanners = _build_scanners()
        browser = FakeBrowserUseEnvCaptureScanner()
        scanners["browser_use"] = browser
        orchestrator = AIAuditOrchestrator(scanners=scanners, llm_client=FakeLLMSelectBrowserUse())
        original_tool_enabled = orchestrator._tool_enabled
        orchestrator._tool_enabled = lambda tool, default=True: (
            True if str(tool or "").strip().lower() == "browser_use" else original_tool_enabled(tool, default)
        )
        original_tool_config = orchestrator._tool_config

        def _tool_config_override(name):
            if str(name or "").strip().lower() == "browser_use":
                cfg = dict(original_tool_config(name) or {})
                cfg.update(
                    {
                        "enabled": True,
                        "timeout_seconds": 900,
                        "max_steps": 25,
                        "headless": True,
                        "api_key": "config-browser-use-test-key",
                        "api_key_env": "",
                    }
                )
                return cfg
            return original_tool_config(name)

        orchestrator._tool_config = _tool_config_override
        output = artifact_path("ai_audit_browser_use_config_api_key_export.json")

        with patch.dict(os.environ, {"BROWSER_USE_API_KEY": "shell-original-key"}, clear=False):
            orchestrator.run(
                "localhost",
                output,
                llm_plan=True,
                max_actions=2,
                use_llm=True,
                compliance_profile="soc2",
                run_browser_use=True,
            )
            self.assertEqual(os.environ.get("BROWSER_USE_API_KEY"), "shell-original-key")

        self.assertTrue(browser.calls)
        first_call = browser.calls[0]
        self.assertEqual(first_call.get("env_browser_use_api_key"), "config-browser-use-test-key")


if __name__ == "__main__":
    unittest.main()
