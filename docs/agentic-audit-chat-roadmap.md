# Agentic Audit, Chat, QA, and Benchmark Roadmap

This document captures the current reasoning for how Supabash should evolve from a strong evidence-collection engine into a smarter, more Codex-like audit system without sacrificing deterministic truth.

It focuses on:

- deterministic evidence/report cleanup
- report linting
- LLM-based report QA overlays
- benchmark-driven quality measurement
- chat/TUI as the primary operator control plane

## Product Goal

Supabash should become:

- deterministic at the evidence layer
- agentic at the decision layer
- reviewed at the report layer
- measured at the benchmark layer
- chat-first at the user layer

The goal is not to add many more commands.

The goal is to let an auditor say something like:

> Check my localhost with the installed security tools on my machine and generate a SOC 2 audit for localhost.

And then have Supabash:

1. understand the request
2. infer the right workflow
3. explain what it intends to do
4. ask for confirmation when needed
5. execute the run
6. critique the results
7. clean up the report
8. present an auditor-friendly output

## Why This Matters

Recent runs show that Supabash is much stronger than before, but the remaining issues are now mostly in:

- evidence hygiene
- summary consistency
- browser fallback noise
- prioritization of top findings
- post-run quality validation

This means the next leap in quality is no longer just “run more tools.”  
It is:

- better deterministic cleanup
- smarter post-run review
- measurable quality gates
- better user interaction through chat/TUI

## Core Architecture Direction

Supabash should keep a strong separation between layers.

### 1. Deterministic Execution Core

This remains the source of truth.

Responsibilities:

- run tools
- collect raw evidence
- normalize findings
- cluster findings
- compute metrics
- write immutable raw artifacts

This layer should stay reproducible and rule-based.

### 2. Agentic Decision Layer

This is the “Codex-like” part.

Responsibilities:

- interpret user intent
- choose workflow
- pick next best action
- critique outcome quality
- update run state
- replan
- stop when evidence gain is exhausted

This should be implemented as:

- planner
- executor coordinator
- critic
- replanner

### 3. Report QA Layer

This sits above deterministic findings.

Responsibilities:

- lint outputs
- detect inconsistencies
- detect malformed evidence
- detect noisy/low-value discoveries
- improve summary quality
- optionally apply structured LLM review overlays

This layer must not silently mutate raw evidence.

### 4. Benchmark / Evaluation Layer

This is how Supabash knows whether it is improving.

Responsibilities:

- run known scenarios
- compare expected vs observed findings
- score run quality
- detect regressions

### 5. Chat / TUI Control Plane

This should become the main operator interface.

Responsibilities:

- natural-language intent handling
- proposing runs
- confirming scope
- launching the shared runtime
- showing status and details
- presenting findings like an analyst

## Recommended Planning Order

The next implementation work should follow this order:

1. Fix deterministic evidence/report bugs from the latest runs.
2. Add a deterministic report lint layer.
3. Add an LLM report QA layer with structured patch output only.
4. Build a SOC2 benchmark matrix with positive, negative, and mixed scenarios.
5. Define quality thresholds so each run can be scored.
6. Rework chat/TUI into the main operator-facing control plane for these workflows.

## Phase 1: Deterministic Bug Fixes

These fixes should happen before more LLM-driven review is added.

High-value bug classes:

- malformed URLs in evidence and discoveries
- summary/detail severity mismatches
- speculative or synthetic discovery noise
- wrong top-finding selection in summary
- browser fallback evidence shaping problems

Examples of deterministic cleanup rules:

- canonical URL sanitization before persistence
- invalid URL rejection
- suppression or down-ranking of 404-only discovery noise
- summary severity derived from canonical cluster max severity
- summary inclusion based on severity, confidence, exploitability, corroboration, and cluster impact

## Phase 2: Deterministic Report Lint

This should be the first post-run reviewer.

It should validate things like:

- summary/detail severity consistency
- malformed URLs
- invalid endpoint references
- 404-only discovery noise
- cluster closure correctness
- broken evidence references
- missing high-signal items in summary
- unsupported wording in compliance language

Expected artifacts:

- `report_lint.json`
- `report_lint.md`

This gives Supabash a reliable rule-based QA layer before any LLM rewriting is allowed.

## Phase 3: LLM Report QA Overlay

After deterministic lint, Supabash can add a structured semantic review step.

Important rule:

- the LLM must not overwrite raw evidence directly

The LLM should act as:

- reviewer
- editor
- prioritization critic

It should not act as:

- source of truth
- freeform finding generator
- raw evidence mutator

### Good LLM QA Tasks

- improve executive summary wording
- identify missing top findings
- detect likely low-value noise in summaries
- improve recommendation phrasing
- improve compliance explanation quality
- suggest finding ranking changes

### Bad LLM QA Tasks

- rewriting raw evidence
- inventing URLs or findings
- changing severity without cluster-backed support
- silently dropping findings from the raw report

### Structured Output Model

The LLM should emit structured review artifacts such as:

- `report_qa.json`
- `report_overrides.json`
- `report_final.json`
- `report_final.md`

The final report should be built from:

- raw evidence
- deterministic normalization
- approved QA overlay

## Phase 4: SOC2 Benchmark Suite

SOC2 is the right first benchmark target because it maps well to the generic engine and current strengths.

### Why SOC2 First

- it is close to general security posture
- it benefits from current scanner coverage
- it maps well to access control, exposure management, monitoring, and configuration issues
- it avoids the overly specialized edges of other profiles at this stage

### Benchmark Scenario Types

For SOC2, the benchmark suite should include:

- positive vulnerable scenarios
- negative protected scenarios
- mixed multi-service scenarios
- stability scenarios
- report-quality fixture scenarios

### Example Scenario Families

- secret exposure
- unauthenticated data-plane exposure
- monitoring/config exposure
- metrics exposure
- object-store exposure
- debug / verbose error exposure

### Why Mixed Scenarios Matter

Many recent bugs were orchestration bugs, not scanner bugs.

So benchmarks must include:

- multiple services at once
- overlapping localhost targets
- same-host different-port cases
- protected and vulnerable services side by side

That is how Supabash proves its cluster closure and target selection logic.

## Phase 5: Quality Thresholds

Each run should be scored.

Recommended metrics:

- high-risk cluster recall
- false-positive high-risk rate
- cluster closure correctness
- summary fidelity
- malformed artifact rate
- duplicate rate
- action efficiency
- target stability impact
- QA correction quality

These scores should eventually be written as benchmark artifacts such as:

- `benchmark_score.json`

## Chat / TUI As Main Operator Interface

The long-term operator UX should be chat-first.

Instead of relying mainly on commands, Supabash should support natural-language tasking like:

- Run a SOC2 audit on localhost.
- Check my local environment for security issues.
- Audit my dev stack and summarize the highest-risk findings.

### Desired Chat Flow

1. Intent detection
   - identify workflow
   - infer target
   - infer compliance profile
   - infer mode

2. Scope and safety check
   - verify allowed scope
   - determine whether confirmation is needed

3. Proposed execution
   - explain what Supabash can run
   - ask whether to proceed

4. Shared runtime execution
   - launch the same engine used by CLI
   - stream progress
   - support stop/status/details

5. Analyst-style review
   - summarize strongest issues
   - explain confidence
   - mention report QA issues
   - propose next steps

## Internal Components To Build Toward

These are internal capabilities, not necessarily new CLI commands:

- `intent_router`
  - turns natural language into workflow plans
- `audit_planner`
  - selects workflows and next actions
- `audit_critic`
  - evaluates result quality and marginal gain
- `report_lint`
  - deterministic post-run validation
- `report_qa`
  - LLM-based structured review
- `benchmark_runner`
  - runs fixture and integration matrices
- `benchmark_scorer`
  - computes quality scores
- `chat_control_plane`
  - owns confirmations, status, details, summaries, and execution proposals

## What To Borrow From Codex-Like Systems

Supabash should not try to become a coding tool.

But it should borrow these patterns:

- iterative planning
- tool-aware execution
- stateful reasoning
- critique and replan
- strong instruction layering
- environment awareness
- operator-friendly interaction

The right use of a Codex-like model later is likely:

- report QA
- remediation patch suggestions
- run comparison and regression explanation
- benchmark triage

Not raw scanner replacement.

## Summary

The next Supabash leap is:

- cleaner deterministic evidence
- stronger report validation
- structured LLM review overlays
- benchmark-driven quality scoring
- a smarter chat/TUI control plane

This is how Supabash becomes smarter like a strong agentic system while remaining trustworthy like a serious security tool.
