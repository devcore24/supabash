# Supabash Audit Workflow (Baseline + Agentic)

This document describes how `ai-audit` selects tools and how the final **Supabash Audit** report is produced. It reflects the current implementation in `src/supabash/ai_audit.py` and `src/supabash/audit.py`.

---

## High-Level Flow

**In short:** `ai-audit` = **`audit.py` baseline + optional agentic expansion**.  
The output is a **Supabash Audit** report intended for compliance preparation and internal review.

1) **Baseline audit (deterministic, no LLM)**
   - Runs the standard audit pipeline with LLM disabled.
   - Produces a complete baseline report.
   - Current baseline order is: fast discovery -> nmap/httpx -> broad nuclei on live web targets -> deep web tools on prioritized targets -> readiness probes -> selective follow-up helpers such as sqlmap/supabase checks.
   - Implemented by calling `AuditOrchestrator.run()` from `audit.py`.

2) **Agentic expansion (optional, tool-calling)**
   - Uses LLM tool-calling to propose additional actions.
   - Executes actions within strict, schema‑validated constraints.

3) **Report assembly (combined)**
   - Merges baseline + agentic results.
   - Recomputes findings, adds optional LLM summary/remediation.
   - Writes a single JSON report (plus optional Markdown/HTML/PDF if enabled).
   - For compliance runs, includes scope assumptions, coverage matrix, not-assessable areas, and recommended next actions.

---

## How `ai-audit` Chooses Tools

### 1) Baseline run comes first
`AIAuditOrchestrator.run()` calls the baseline audit with `use_llm=False`.  
This ensures the core pipeline always runs, even if the LLM fails.

### 2) Allowed tools are explicitly filtered
The agentic phase only allows tools that:
- Are installed and registered
- Are enabled in config
- Match the target type (web, domain, SMB, TLS, container, etc.)
- Respect opt‑in flags (e.g., `nikto`)
- Respect runtime gates (for example `browser_use` is allowed by default when available, and can be disabled with `--no-browser-use`)
- Respect tool credentials/runtime requirements (for `browser_use`, Supabash can use `tools.browser_use.api_key`, `tools.browser_use.api_key_env`, or `BROWSER_USE_API_KEY` from the running shell)
- Respect browser-use runtime controls (`tools.browser_use.require_done`, `tools.browser_use.min_steps_success`) so incomplete browser runs are rejected

### 3) Tool calls are schema‑constrained
The LLM must respond using the `propose_actions` tool schema:

```json
{
  "actions": [
    {
      "tool_name": "nuclei",
      "arguments": {
        "profile": "standard",
        "target": "http://example.com",
        "rate_limit": 10
      },
      "reasoning": "..."
    }
  ],
  "stop": false,
  "notes": "..."
}
```

The schema enforces:
- Allowed tools only
- Only allowed argument keys
- Required `profile` field (`fast|standard|aggressive|compliance_*`)

### 4) Outputs are normalized and bounded
Even if the model proposes a tool:
- Targets are validated against allowed lists
- Threads/rate limits are clamped
- Compliance profiles can override aggressive settings

Baseline-specific notes:
- Broad baseline `nuclei` is distinct from targeted follow-up `nuclei`.
- `tools.nuclei.rate_limit` is the normal default for both.
- `tools.nuclei.normal_mode_broad_rate_limit` is optional and only affects the broad multi-target baseline pass in `normal` mode.
- If `tools.nuclei.normal_mode_broad_rate_limit=0`, Supabash fully honors `tools.nuclei.rate_limit`.

### 4.1) Browser-use tasking and feedback loop
For `browser_use` actions, Supabash composes an evidence-aware task brief that includes:
- Planner rationale/hypothesis/expected evidence
- Target-specific prior findings (when available)
- Optional configured auth context hints (`tools.browser_use.auth.*`)
- An exact allowed-origin list enforced by the browser-use Python library

After execution, browser observations (completion status, steps, findings/URLs) are added back to run state so the next planner iteration sees what was already tried and what evidence was produced.
Guarded execution requires the Python-library path with native `Browser.allowed_domains` enforcement. Named sessions, custom commands, and the native CLI fail closed; the former deterministic CLI fallback is deprecated and disabled because it cannot prevent cross-origin navigation.
Browser-discovered URLs are post-validated with `httpx` before they materially influence gain or cluster closure.
Use the structured `httpx` wrapper for deterministic endpoint validation rather than browser CLI fallback.

### 4.2) Coverage-debt prioritization and stopping
Supabash tracks open HIGH/CRITICAL finding clusters during the run.

- If high-risk coverage debt remains open, the planner prioritizes actions linked to those clusters first.
- Endpoint-level targets are preserved for follow-up actions (for example `/api/v1/status/config`, `/rest/v1/`) instead of collapsing them back to `/`.
- If normal candidates are exhausted, Supabash can synthesize fallback `httpx` / `browser_use` / `nuclei` actions directly from unresolved cluster evidence.
- Once high-risk clusters are closed and recent marginal gain is low, the planner stops with a post-closure diminishing-returns decision instead of spending low-value cleanup actions.
- Endpoint-level browser observations can close matching high-risk clusters when the target/path and risk family align; broad host-only correlation is intentionally constrained.

### 5) Graceful fallback is built‑in
With the legacy backend, unsupported provider tool-calling skips the agentic phase and still writes the baseline report. With the opt-in Codex backend, preflight happens before baseline scanning; a preflight failure starts no scan. A later Codex failure preserves collected evidence but marks the report failed.

The Codex backend must be launched from a standalone WSL/Linux terminal. Supabash rejects nested launches from Codex or ChatGPT app tasks before preflight or scanning so ambient task instructions cannot become planner context. It also rejects non-empty or symlinked global `AGENTS.md`/`AGENTS.override.md` files in the effective Codex home; use an empty normal home or a separately authenticated `codex.codex_home`. `supabash doctor --codex` checks both boundaries together with the installed CLI version, required non-interactive flags, and ChatGPT authentication.

### LLM Enablement
The default `legacy` backend follows `llm.enabled` and `--no-llm`; disabling the LLM keeps the run baseline-only. The explicit `--agent-backend codex` path uses the separate `codex` configuration and requires planning, so it rejects `--no-llm` and `--no-llm-plan` instead of silently downgrading.

---

## How the Final Report Is Produced

1) **Baseline results recorded** with `phase="baseline"`
2) **Agentic actions recorded** with `phase="agentic"` and `reasoning`
3) Results are **stably sorted** for deterministic ordering
4) Findings are **recomputed** from the combined results
5) Optional **LLM summary/remediation** is applied (if enabled)
6) Optional **compliance tags** are added
7) JSON report is written; Markdown/HTML/PDF are optional exports

The combined report also exposes run-quality metrics such as:
- total/unique/duplicate findings
- duplicate rate
- agentic net-new unique findings
- open high-risk cluster count
- covered cluster count

---

## Key Guarantees

- Baseline audit runs for normal and ready agentic backends. A requested Codex backend must pass its preflight first, so an unavailable Codex installation causes a clean failure before scanning.
- Tool calling cannot bypass hard constraints or enable disabled tools.
- Codex is a schema-constrained planner only: it runs read-only in an empty private workspace with user config, rules, global AGENTS instructions, generated context, web access, and direct tool features disabled or rejected. Supabash remains the only scanner executor.
- Codex protocol capture fails closed on incomplete, malformed, truncated, unknown-action, or direct-tool events. The optional trace contains bounded structural metadata rather than raw model or tool payloads.
- Report output is deterministic and auditable.
- Low-signal duplicate `INFO` findings are suppressed in the final finding list while raw tool evidence remains preserved in the evidence/result artifacts.
- Deep web follow-up can skip a target that becomes unavailable after baseline pressure instead of continuing to hammer an unhealthy service.
- Disabled tools should be recorded as skipped rather than being reported as if they ran.
