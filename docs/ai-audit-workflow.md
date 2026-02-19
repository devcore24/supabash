# Supabash Audit Workflow (Baseline + Agentic)

This document describes how `ai-audit` selects tools and how the final **Supabash Audit** report is produced. It reflects the current implementation in `src/supabash/ai_audit.py` and `src/supabash/audit.py`.

---

## High-Level Flow

**In short:** `ai-audit` = **`audit.py` baseline + optional agentic expansion**.  
The output is a **Supabash Audit** report intended for compliance preparation and internal review.

1) **Baseline audit (deterministic, no LLM)**
   - Runs the standard audit pipeline with LLM disabled.
   - Produces a complete baseline report.
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
- Respect tool credentials/runtime requirements (for `browser_use`, set `BROWSER_USE_API_KEY` in the same shell/session running `supabash`)
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

### 4.1) Browser-use tasking and feedback loop
For `browser_use` actions, Supabash composes an evidence-aware task brief that includes:
- Planner rationale/hypothesis/expected evidence
- Target-specific prior findings (when available)
- Optional configured auth context hints (`tools.browser_use.auth.*`)
- Optional auto-session isolation (`tools.browser_use.auto_session=true`) when no explicit session is configured

After execution, browser observations (completion status, steps, findings/URLs) are added back to run state so the next planner iteration sees what was already tried and what evidence was produced.
If browser-use returns an incomplete run (`done=false`), Supabash can perform deterministic browser probes (`open/state/get`) as a fallback (`tools.browser_use.allow_deterministic_fallback`) and merge that evidence back into planner context.

### 5) Graceful fallback is built‑in
If tool‑calling fails or isn’t supported, Supabash skips the agentic phase and still writes the baseline report.

### LLM Enablement
`ai-audit` only uses the LLM when `llm.enabled=true` in `config.yaml`.  
If `llm.enabled=false` (or `--no-llm` is passed), the run stays baseline‑only.

---

## How the Final Report Is Produced

1) **Baseline results recorded** with `phase="baseline"`
2) **Agentic actions recorded** with `phase="agentic"` and `reasoning`
3) Results are **stably sorted** for deterministic ordering
4) Findings are **recomputed** from the combined results
5) Optional **LLM summary/remediation** is applied (if enabled)
6) Optional **compliance tags** are added
7) JSON report is written; Markdown/HTML/PDF are optional exports

---

## Key Guarantees

- Baseline audit always runs (agentic is optional).
- Tool calling cannot bypass hard constraints or enable disabled tools.
- Report output is deterministic and auditable.
