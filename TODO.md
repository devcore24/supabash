# 📝 Supabash Development Roadmap

This document outlines the step-by-step tasks required to build **Supabash**, the AI-driven security audit agent.

---

## 🎯 Phase 11: Autonomous Agentic Audit Kernel (Current)
*Goal: make `ai-audit` behave like a true iterative security analyst loop (observe → reason → act → reassess), prioritizing adaptive autonomy over fixed list execution.*

- [x] **Iterative best-next-action loop (single-step planning)**
    - [x] Change planner behavior to select one highest-value next action per cycle (instead of broad batches).
    - [x] Re-plan after each action using newly collected evidence.
    - [x] Prevent repetitive low-yield actions with explicit duplicate/saturation guards.
- [x] **Hypothesis-driven action schema**
    - [x] Extend planner action schema with `hypothesis`, `expected_evidence`, and `priority`.
    - [x] Capture these fields in stored agentic actions for audit reasoning transparency.
    - [x] Add parsing/validation fallbacks so older planner responses continue to work.
- [x] **Decision Trace + Replay JSON artifact**
    - [x] Persist an `ai_audit.decision_trace` in report JSON (planner candidates, chosen action, outcome signal, critique).
    - [x] Emit sidecar replay file per run (`<slug>-replay.json`) with ordered steps and run context.
    - [x] Link replay artifact in report output for easy rerun/reconstruction.
- [x] **Autonomous post-action critique**
    - [x] Add deterministic post-action signal extraction (new findings count, target expansion, skip/failure reason class).
    - [x] Feed critique summary back into next planning cycle.
    - [x] Stop early when evidence gain saturates or planner explicitly signals stop.
- [ ] **Shared runtime path for `ai-audit` and chat `/audit`**
    - [ ] Ensure both entry points use the same iterative agent loop implementation.
    - [ ] Keep status events/progress messaging aligned across CLI and chat.
- [ ] **Regression tests for autonomous loop**
    - [ ] Unit tests for action normalization with new schema fields.
    - [x] Tests for replay artifact creation and markdown visibility.
    - [ ] Tests for iteration behavior (one primary action per cycle + replan).

---

## 🎯 Phase 9: Readiness Report Clarity Sprint (Current)
*Goal: make Supabash readiness reports clearer and more auditor-usable than manual experimental reports while staying deterministic.*

- [x] **Correlate and de-duplicate key findings in summary**
    - [x] Merge equivalent findings from multiple tools into one canonical summary finding.
    - [x] Preserve tool corroboration as merged evidence bullets (instead of repeating findings).
    - [x] Add deterministic grouping rules and keep stable ordering.
- [x] **Attach explicit evidence references to key findings**
    - [x] Include direct artifact references (`evidence/...`) where available.
    - [x] Include manifest linkage guidance for each key finding.
- [x] **Improve compliance coverage matrix evidence attribution**
    - [x] Ensure matrix rows cite tools that actually produced evidence in the run.
    - [x] Avoid stale/default evidence sources in compliance rows.
    - [x] Prevent false-positive evidence attribution when a tool run is successful but has no meaningful exposure signal.
- [x] **Tighten SOC2 mapping quality**
    - [x] Add mapping rationale + confidence for summary-level findings.
    - [x] Continue using softened wording (`Potential Gap`, `Requires Validation`).
    - [x] Remove duplicate compliance label rendering (`Potential Gap: Potential Gap: ...`).
- [x] **Add explicit “Not Assessable Automatically” section**
    - [x] List SOC2 areas that network/web scans cannot validate automatically.
    - [x] Keep this section deterministic and profile-aware.
- [x] **Add action-oriented closure section**
    - [x] Add deterministic `Recommended Next Actions` to improve audit-readability and remediation handoff.
- [x] **Reduce detailed findings noise while preserving traceability**
    - [x] Add correlated-view hints for repeated findings with same endpoint/control signal.
    - [x] Keep full raw evidence in manifest artifacts.
- [x] **Maintain format parity (MD/HTML/PDF)**
    - [x] Ensure summary + matrix sections render identically across formats.
    - [x] Keep table readability and avoid wrapped header/word splitting regressions.
- [x] **CI regression tests for report clarity**
    - [x] Snapshot tests for summary correlation and matrix attribution.
    - [x] Keep deterministic order and counts across repeated runs.

---

## 🎯 Phase 10: Readiness Depth Sprint (Next)
*Goal: improve control-depth signal without sacrificing deterministic output quality.*

- [x] **Expand compliance mapping breadth**
    - [x] Add deterministic control-family mappings for common service-exposure findings across all profiles.
    - [x] Keep mapping confidence explicit and avoid hard non-compliance wording.
- [x] **Add deterministic next-actions by profile**
    - [x] Extend `Recommended Next Actions` with profile-aware ordering (SOC2/PCI/ISO/…).
    - [x] Add unit tests for action generation stability.
- [x] **Coverage matrix quality improvements**
    - [x] Add optional `coverage_basis` field to make evidence-source decisions explicit in JSON.
    - [x] Ensure rows fall back to `Not Assessed` when signal is inconclusive.

---

## 🏗️ Phase 1: Foundation & Architecture
*Goal: Set up the project structure, dependency management, and installation scripts.*

- [x] **Project Initialization**
    - [x] Create git repository and standard folder structure (`/src`, `/tests`, `/docs`).
    - [x] Create virtual environment setup (`python -m venv venv`).
    - [x] Initialize `requirements.txt` (Typer, Rich, OpenAI, Subprocess, etc.).
    - [x] **Logging System:** Implement file-based logging for debugging (rotational logs in `~/.supabash/logs`).
        - [x] Honor `core.log_level` from `config.yaml`.
        - [x] Use a shared rotating handler to avoid duplicate log entries.
- [x] **The "One-Command" Installer (`install.sh`)**
    - [x] Write Bash script to detect OS (Debian/Ubuntu/Kali).
    - [x] Implement `apt-get` logic for system binaries (nmap, nikto, sqlmap, etc.).
    - [x] Add specific installation logic for external tools (Nuclei, Trivy).
    - [x] Update Nuclei templates post-install (best-effort, non-root user).
    - [x] Install Trivy repository key via `/etc/apt/keyrings` (no `apt-key`).
    - [x] Add Python dependency installation step.
    - [x] Create the global entry point (symlink `supabash` to `/usr/local/bin`).
- [x] **CLI Skeleton (Python)**
    - [x] Set up `Typer` application entry point.
    - [x] Design the ASCII Art Banner (The "Bashing" theme).
    - [x] Create placeholder commands: `scan`, `audit`, `config`, `chat`.
- [x] **Configuration Manager**
    - [x] Create a config handler (YAML/JSON) to store API Keys and default settings.
    - [x] Implement `supabash config` command to set keys interactively.
    - [x] Allow managing `core.allowed_hosts` and `core.consent_accepted` via CLI flags.

---

## 🛠️ Phase 2: The "Hands" (Tool Wrappers)
*Goal: Enable Python to execute Linux security binaries and capture their output.*

- [x] **Command Execution Engine**
    - [x] Create a `CommandRunner` class to handle `subprocess` calls safely.
    - [x] Implement timeout handling (so Nmap doesn't hang forever).
    - [x] Implement robust error handling and output decoding.
- [x] **Recon Module Wrappers**
    - [x] **Nmap:** Parse XML/Greppable output into JSON.
    - [x] **Masscan/Rustscan:** Wrapper for high-speed port discovery.
        - [x] Masscan wrapper with list-output parser.
        - [x] Rustscan wrapper with greppable parser.
    - [x] **CLI Integration:** Allow selecting Nmap/Masscan/Rustscan via `--scanner`.
    - [x] **Subfinder:** Subdomain discovery (opt-in; best results with provider API keys).
    - [x] **HTTP Probing:** Add `httpx` wrapper to validate live web URLs before web tools run.
    - [x] **Tech Detection:** Integrate `WhatWeb` or simple HTTP header analysis.
    - [x] **TLS Checks:** Add `sslscan` wrapper (runs when 443/8443 detected).
    - [x] **DNS Enum:** Add `dnsenum` wrapper (runs for domain targets).
    - [x] **SMB Enum:** Add `enum4linux-ng` wrapper (runs when 139/445 detected).
- [x] **Web Module Wrappers**
    - [x] **Nikto:** Wrapper for server config scanning.
    - [x] **Nuclei:** Wrapper for template-based scanning (Crucial for modern CVEs).
    - [x] **Gobuster:** Wrapper for directory brute-forcing.
    - [x] **ffuf:** Wrapper for content discovery (opt-in; can be used as a fallback when Gobuster fails).
    - [x] **Katana:** Wrapper for crawling/spidering (opt-in; expands attack surface beyond brute-force).
    - [x] **Searchsploit:** Wrapper for offline exploit reference lookup (opt-in; informational only, no exploitation).
- [x] **SQL & Auth Wrappers**
    - [x] **Sqlmap:** Wrapper for automated SQL injection detection.
    - [x] **Hydra:** Wrapper for service authentication brute-forcing.
- [x] **Container Module**
    - [x] **Trivy:** Wrapper to scan local Docker images.
- [x] **Supabase Specific Module**
    - [x] Implement the RLS (Row Level Security) checker for Supabase URLs.
    - [x] Wire into audit aggregation (report.json output).
    - [x] Consolidate Supabase checks (RLS + URL/key/RPC exposure).
    - [ ] Harden Supabase audit coverage (expand test matrix; reduce false negatives/positives).
- [ ] **Firebase Specific Module (Planned)**
    - [ ] Detect exposed Firebase project URLs and API keys in web content.
    - [ ] Probe public Firestore/Realtime Database rules (read/write exposure).
    - [ ] Check Storage bucket access policies for public exposure signals.
- [x] **Wireless Module (Experimental)**
    - [x] **Aircrack-ng:** Basic wrapper for monitoring and capturing (requires hardware access).

---

## 🧠 Phase 3: The "Brain" (AI Integration)
*Goal: Connect the tools to the LLM so it can reason about the results.*

- [x] **LLM Client Setup**
    - [x] Integrate litellm client with provider/model selection from config.
    - [x] (Optional) Add support for local models (Ollama/LM Studio/Mistral) for offline privacy.
- [x] **Prompt Engineering**
    - [x] Design the "Analyzer" prompt: Input = Tool Output -> Output = Vulnerability Summary.
    - [x] Design the "Planner" prompt: Input = Current State -> Output = Next Tool to run.
    - [x] Design the "Remediator" prompt: Input = Vulnerability -> Output = Code Fix.
- [x] **Interactive Chat Interface**
    - [x] Implement `supabash chat` command with slash commands (/scan, /details, /report, /test).
    - [x] Add `/audit` slash command (runs the same audit pipeline as CLI).
    - [x] Support `/details <tool>` to inspect per-tool audit output.
    - [x] Add LLM-backed summary and remediation commands (/summary, /fix).
    - [x] Enable the agent to ask clarifying questions to the user.
    - [x] Make chat `/audit` write timestamped reports to `reports/` by default (JSON + Markdown).
    - [x] Accept `target=...` style tokens in slash commands (e.g., `/audit target=localhost`).
    - [x] Chat workflow:
        - Single session as control plane; acknowledge and confirm scope before running tools.
        - [x] Support slash commands (e.g., `/scan`, `/audit`, `/stop`, `/status`, `/details`, `/report`, `/test`) without leaving chat.
        - [x] Run tools/tests in background workers and stream progress via `/status` (chat remains responsive).
            - `/stop` sends a cancel request and terminates running tool processes (best-effort).
        - [x] Stream progress for long-running tools (checkpoints/heartbeats) via `/status --watch`; offer `/details <tool>` for full output.
        - Keep safety checks in-line: enforce allowed-hosts/rate limits; block out-of-scope requests.
    - [x] Allow resume if disconnected (reload last scan/audit state from disk).
    - [x] Show progress feedback in chat for long-running actions (LLM “Thinking…” + job running hints).
    - [x] **Chat Memory & Context Awareness**
        - [x] Conversation history: persist `messages[]` (user/assistant/tool events) in chat state.
        - [x] Include the last N turns in every LLM call (configurable via `chat.llm_history_turns`).
        - [x] Rolling summary memory: maintain `conversation_summary` updated every few turns to stay context-aware.
        - [x] Tool-context weaving: attach current target + scope + last results + current plan into prompts.
        - [x] Agent loop UX: freeform chat proposes a command; runs only after explicit confirmation (`y/yes`).
        - [x] Safety/privacy: redact secrets in chat history; optional local-only LLM mode (`llm.local_only=true`).
        - [x] Show context window usage (%) for each LLM call (best-effort; set `llm.max_input_tokens` for local models).
- [x] **AI Audit (Baseline + Agentic Expansion)**
    - [x] Add `supabash ai-audit` command (and `audit --agentic` alias).
    - [x] Run baseline audit without LLM for determinism.
    - [x] Add bounded agentic expansion phase (covers additional discovered web targets).
    - [x] Report includes run type + agentic expansion section.
    - [x] Add unit tests for `ai-audit` and the alias flags.
- [x] **Context & Cost Management**
    - [x] Implement a token limiter to ensure tool output doesn't crash the LLM context window (truncate large Nmap results).
    - [x] Implement token usage tracking and cost estimation.
    - [x] Implement basic prompt caching to save costs.

---

## 🛡️ Phase 4: Safety & Logic
*Goal: Ensure the agent behaves ethically and doesn't break things.*

- [x] **Scope Control (CRITICAL)**
    - [x] Implement a strict "Allowed Hosts" check.
        - [x] Support CIDR and wildcard host patterns; accept URL inputs (hostname extraction).
    - [x] Prevent the agent from scanning unverified public IPs.
        - [x] Block IP-literal targets by default when they are public/global.
        - [x] Opt-in via `core.allow_public_ips` or `--allow-public`.
- [x] **Legal & Consent**
    - [x] Implement consent prompt for scan/audit (with override flag).
    - [x] Persist consent acceptance in config (`core.consent_accepted`).
- [x] **Traffic Control**
    - [x] Add flags for "Stealth Mode" vs "Aggressive Mode".
    - [x] Implement rate limiting options (masscan/rustscan/nuclei/gobuster tuning flags).

---

## 📊 Phase 5: Reporting & Audit
*Goal: Turn scan data into a valuable document for developers.*

- [x] **Data Aggregation**
    - [x] Create a standard JSON schema for findings (Severity, Description, Evidence, Fix).
- [x] **Report Generators**
    - [x] **JSON Report:** For machine integration.
    - [x] **Markdown Report:** A pretty, readable audit file with sections.
    - [x] Auto-generate Markdown alongside JSON (same timestamped filename).
- [x] **Code Fix Generator**
    - [x] Ensure the AI provides specific code snippets (e.g., "Change line 40 in Dockerfile to...").

---

## 🧪 Phase 6: Testing & Polish
*Goal: Quality assurance.*

- [x] **Unit Testing**
    - [x] Test the parsers (Does the Nmap parser actually catch open ports?).
    - [x] Test the argument builders.
- [x] **Integration Testing**
    - [x] Add docker-based harness (`docker-compose.integration.yml`) and docs.
    - [x] Spin up a deliberately vulnerable container (e.g., `dvwa` or `juiceshop`) (opt-in).
    - [x] Run Supabash against it to verify the web toolchain executes (opt-in).
- [x] **Performance Tuning**
    - [x] Optimize async execution (can we run Gobuster and Nmap at the same time?).

---

## 📚 Phase 7: Documentation
- [x] Write `README.md` (Done).
- [x] Create a `CONTRIBUTING.md`.
- [x] Document the tool requirements for users who don't use the installer.

---

## 🚧 Phase 8: Hardening & UX (Post-MVP)
*Goal: Make Supabash safer, more predictable, and easier to operate at scale.*

- [x] Add `supabash doctor` environment checks (binaries + config).

- [x] Add plugin/tool registry (enable/disable tools in `config.yaml`).
- [x] Add per-tool timeouts in config (e.g. `tools.nmap.timeout_seconds`).
- [x] Make parallel tool results deterministic (stable ordering in reports).
- [x] Include exact commands executed in reports (auditability).
- [x] Add report schema versioning + validation.
- [x] Add safety caps for aggressive mode (global rate limits).
- [x] Add CI workflow to run unit tests automatically.
- [x] Add packaging/release guide (pip/standalone binary).
- [x] Improve Markdown report styling (anchors, tables, collapsible sections).
- [x] Add explicit offline/no-LLM mode (graceful degradation).
- [x] Add more opt-in integration targets beyond Juice Shop.
- [x] Add OSINT/LAN CLI flags for theHarvester + netdiscover.
- [x] Add opt-in CLI flags for Medusa + CrackMapExec with report findings.
- [x] Add cloud posture tooling (ScoutSuite + Prowler) with opt-in flags and report findings.
- [ ] Harden cloud posture coverage (beta today; expand checks, validate findings).
- [x] Add tool-calling agentic planning for AI audit (structured schema with profile + graceful fallback).
- [x] Map compliance profiles (PCI, SOC2, ISO, DORA, NIS2, GDPR, BSI) to agentic tool settings.
    - [x] Add compliance profiles to agentic schema and enforce audit-grade reasoning.
    - [x] Apply profile-driven tool settings and compliance annotations in reports.
    - [x] Surface compliance focus in report methodology for audit traceability.

### Next Tool Additions (Planned)
- [x] **sslscan:** TLS configuration checks (run only when HTTPS ports are open).
- [x] **dnsenum:** DNS enumeration (run only for domain targets).
- [x] **enum4linux-ng:** SMB enumeration helper (run only when 445/139 are open).
- [x] Wire **Nikto** into the audit flow (opt-in via `--nikto`, runs on discovered web targets).
- [x] Wire **Hydra** into the workflow (opt-in; requires explicit user-provided credential lists).
- [x] Add **ffuf** (opt-in content discovery; fallback when Gobuster refuses wildcard/soft-404 targets).
- [x] Add **subfinder** (opt-in subdomain discovery; feeds additional web targets into probing).
- [x] Add **katana** (opt-in crawl/spider to expand discovered endpoints).
- [x] Add **Searchsploit** (opt-in offline exploit reference lookup derived from service fingerprints).
- [x] Add **WPScan** (WordPress security scanner; runs when WordPress is detected via WhatWeb).
- [x] Add **theHarvester** (OSINT reconnaissance; harvests emails, subdomains, hosts from public sources).
- [x] Add **Netdiscover** (ARP reconnaissance for local network host discovery).
- [x] Add **CrackMapExec/NetExec** (AD/Windows post-exploitation; SMB enumeration, pass-the-hash).
- [x] Add **Medusa** (parallel network login brute-forcer; alternative to Hydra).
- [x] Add **ScoutSuite** (multi-cloud posture assessment; AWS/Azure/GCP).
- [x] Add **Prowler** (AWS security best-practice checks).
- [ ] Expand cloud posture validation (baseline coverage is beta/WIP).
- [x] Add **Aircrack-ng:** WiFi security auditing (requires hardware; experimental).

### Future Tool Additions (Backlog)
- [ ] **Recon-ng:** Web reconnaissance framework with modular OSINT capabilities.
- [ ] **Shodan CLI:** Query Shodan for exposed services (requires API key).
- [ ] **Impacket Tools:** Network protocol manipulation for Windows/AD environments.
- [ ] **John the Ripper:** Offline password cracking for captured hashes.
- [ ] **Hashcat:** GPU-accelerated password recovery.
