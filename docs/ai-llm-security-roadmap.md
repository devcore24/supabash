# AI / LLM Security Roadmap

This document captures the current reasoning for how Supabash should expand into AI / LLM red-team and blue-team security work without turning the CLI into a pile of special-purpose commands.

## Why This Matters

AI application security is moving fast. A modern audit tool should not only scan hosts, web apps, and infrastructure, but also reason about:

- prompt injection
- insecure output handling
- tool misuse
- RAG poisoning
- memory poisoning
- MCP / agent runtime abuse
- secret disclosure
- unsafe autonomous actions

Supabash already has useful building blocks for this direction:

- agentic planning
- replay traces
- LLM traces
- evidence-backed reporting
- browser-driven validation

That makes it a strong base for AI security work, but only if the design stays current and does not overfit to one jailbreak repo or one benchmark target.

## Current Framing

As of March 1, 2026, Supabash should align to current GenAI security language, not older shorthand.

- OWASP GenAI / LLM Top 10 2025:
  - `LLM01:2025` Prompt Injection
  - `LLM02:2025` Sensitive Information Disclosure
  - `LLM05:2025` Improper Output Handling
- OWASP agentic application guidance is also now relevant for tool-using systems, autonomous workflows, and MCP-style integrations.

Practical consequence:

- Supabash should not frame everything as "jailbreaks"
- Supabash should evaluate end-to-end exploitability and business impact
- findings should map to current OWASP GenAI / agentic language

## What Repos Like L1B3RT4S Are Good For

Reference repo:

- https://github.com/elder-plinius/L1B3RT4S

Collections like L1B3RT4S are useful as:

- attack payload corpora
- provider-specific prompt ideas
- mutation seeds
- regression inputs
- threat-intel style references for prompt leakage and jailbreak attempts

They are not enough as a complete architecture.

Why not:

- they do not model targets well
- they do not validate real sinks
- they do not score impact cleanly
- they do not provide blue-team control validation
- they do not provide a universal replayable audit harness

Supabash should treat these repos as inputs, not as the engine.

## The Core Product Direction

Supabash should become a scenario-driven AI security harness.

The core unit should be:

`target + attack family + execution context + sink + evidence + replay`

This is better than simply asking:

- did the model comply with a jailbreak
- did the model reveal a prompt
- did the model say something unsafe

Instead, Supabash should ask:

- did untrusted input override instructions
- did the app exfiltrate secrets
- did the model call tools with attacker-controlled arguments
- did unsafe output reach a browser, shell, SQL engine, or API sink
- did retrieval or memory poison later decisions
- did an agent bypass approval or auth boundaries

## Red-Team And Blue-Team Meaning Inside Supabash

These should be internal capability modules, not necessarily new user-facing commands.

The preferred UX is:

- one main AI security workflow
- minimal extra command surface
- internal planners decide whether the run is acting in a red-team, blue-team, benchmark, or regression capacity

So terms like `ai_red`, `ai_blue`, or `ai_bench` are best thought of as internal modules or workflows, not required CLI commands.

### User-Facing Principle

Keep one main entrypoint:

- `supabash ai-audit ...`
- chat-driven AI audit requests

The agent should decide internally whether to:

- generate attacks
- validate defenses
- replay regressions
- map findings to OWASP / ATLAS

This keeps the tool agentic and reduces command clutter.

## Recommended Internal Architecture

These are internal engine modules, not necessarily commands:

- `ai_targeting`
  - classify the target: chatbot, RAG app, agent, MCP server, coding agent, API wrapper, browser agent
- `ai_red`
  - attack generation, payload mutation, injection campaigns, evasion attempts
- `ai_blue`
  - guardrail validation, approval checks, secret redaction checks, policy enforcement checks
- `ai_bench`
  - replay successful attacks and compare before/after changes
- `ai_sinks`
  - evaluate impact on real sinks such as shell, SQL, browser, markdown, tool calls, secrets, data exfiltration
- `ai_policies`
  - map findings to OWASP GenAI 2025, OWASP agentic guidance, and MITRE ATLAS

## Design Principles

### 1. Keep The Main Interface Small

Do not explode the CLI into many niche commands.

Prefer:

- one main AI audit workflow
- flags or inferred modes only when necessary
- chat and planner-driven operation

### 2. Score Impact, Not Just Prompt Success

A strong AI security tool should prioritize:

- real secret disclosure
- unsafe tool execution
- unsafe output reaching a downstream sink
- auth / approval bypass
- poisoning that persists into later decisions

This is more valuable than counting "jailbreak wins."

### 3. Treat Browser / Tool / Agent Context As First-Class

Model-only testing is not enough anymore.

Supabash should support:

- model-only targets
- RAG applications
- tool-using agents
- browser agents
- coding agents
- MCP-connected systems

### 4. Preserve Replayability

Supabash already stores replay and LLM trace artifacts. That is a strong foundation.

AI security work should keep:

- replayable attack runs
- evidence of the exact sink reached
- exact prompts, responses, tool calls, and follow-on actions

### 5. Stay Universal

Do not overfit to:

- one lab target
- one provider
- one jailbreak corpus
- one framework

The engine should operate on general classes of AI systems and attack surfaces.

## Highest-Value Initial Scope

The best first focus areas are:

1. `LLM01:2025` Prompt Injection
2. `LLM05:2025` Improper Output Handling
3. sensitive information disclosure
4. tool / MCP misuse
5. RAG poisoning and memory poisoning

Why this order:

- they are high-impact
- they are broadly applicable
- they benefit from Supabash's existing agentic, browser, and evidence/report pipeline

## What "Ultimate" Looks Like

For red teams, Supabash should eventually test:

- direct prompt injection
- indirect prompt injection via web pages, markdown, PDFs, tickets, commits, and retrieved docs
- system prompt leakage
- tool-call hijacking
- MCP and agent runtime misuse
- memory poisoning
- RAG poisoning
- unsafe code or output reaching real sinks

For blue teams, Supabash should eventually validate:

- input filtering
- prompt isolation
- tool allowlists
- auth gates
- schema enforcement
- output sanitization
- secret redaction
- approval steps
- regression safety after changes

## External Resources To Track

These are useful references to keep the roadmap current:

- OWASP GenAI project: https://genai.owasp.org/
- OWASP LLM Top 10 2025: https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- OWASP Secure MCP Server Development Guide: https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- MITRE ATLAS data: https://github.com/mitre-atlas/atlas-data
- L1B3RT4S: https://github.com/elder-plinius/L1B3RT4S
- PyRIT: https://github.com/Azure/PyRIT
- garak: https://github.com/NVIDIA/garak
- promptfoo: https://github.com/promptfoo/promptfoo
- Inspect: https://inspect.aisi.org.uk/
- LLM Guard: https://github.com/protectai/llm-guard
- NeMo Guardrails: https://github.com/NVIDIA-NeMo/Guardrails
- PurpleLlama: https://github.com/meta-llama/PurpleLlama
- Microsoft AI Red Teaming Playground Labs: https://github.com/microsoft/AI-Red-Teaming-Playground-Labs

## Recommended Near-Term Direction For Supabash

1. Build an AI target model that understands chatbot, RAG, agent, browser, coding-agent, and MCP cases.
2. Add sink-aware evaluators so findings are about exploitability, not just prompt compliance.
3. Ingest jailbreak / payload corpora like L1B3RT4S as inputs, not architecture.
4. Add agent, tool, and MCP-specific scenarios before chasing more prompt collections.
5. Add blue-team regression suites that replay successful attacks after fixes or guardrail changes.
6. Keep the user-facing interface simple: one main AI audit workflow, modular internals.

## Summary

The goal is not to bolt a jailbreak pack onto Supabash.

The goal is to make Supabash a universal, agentic AI security audit system that can:

- discover AI attack surfaces
- generate and mutate attacks
- validate exploitability at real sinks
- assess defensive controls
- replay successful attacks
- produce evidence-backed findings aligned to current GenAI security guidance

That direction fits Supabash better than a command-heavy design and keeps the project aligned with how AI security is actually evolving.
