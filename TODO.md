# 📝 Supabash Development Roadmap

This document outlines the step-by-step tasks required to build **Supabash**, the AI-driven security audit agent.

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
    - [x] **Tech Detection:** Integrate `WhatWeb` or simple HTTP header analysis.
- [x] **Web Module Wrappers**
    - [x] **Nikto:** Wrapper for server config scanning.
    - [x] **Nuclei:** Wrapper for template-based scanning (Crucial for modern CVEs).
    - [x] **Gobuster:** Wrapper for directory brute-forcing.
- [x] **SQL & Auth Wrappers**
    - [x] **Sqlmap:** Wrapper for automated SQL injection detection.
    - [x] **Hydra:** Wrapper for service authentication brute-forcing.
- [x] **Container Module**
    - [x] **Trivy:** Wrapper to scan local Docker images.
- [x] **Supabase Specific Module**
    - [x] Implement the RLS (Row Level Security) checker for Supabase URLs.
    - [x] Wire into audit aggregation (report.json output).
- [ ] **Wireless Module (Experimental)**
    - [ ] **Aircrack-ng:** Basic wrapper for monitoring and capturing (requires hardware access).

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
    - [x] Chat workflow:
        - Single session as control plane; acknowledge and confirm scope before running tools.
        - [x] Support slash commands (e.g., `/scan`, `/audit`, `/stop`, `/status`, `/details`, `/report`, `/test`) without leaving chat.
        - [x] Run tools/tests in background workers and stream progress via `/status` (chat remains responsive).
            - `/stop` sends a cancel request and terminates running tool processes (best-effort).
        - [x] Stream progress for long-running tools (checkpoints/heartbeats) via `/status --watch`; offer `/details <tool>` for full output.
        - Keep safety checks in-line: enforce allowed-hosts/rate limits; block out-of-scope requests.
        - [x] Allow resume if disconnected (reload last scan/audit state from disk).
- [x] **The "ReAct" Loop (Reason + Act)**
    - [x] Implement the main agent loop:
        1.  Analyze Goal.
        2.  Select Tool.
        3.  Execute Tool.
        4.  Read Output.
        5.  Decide next step or Finish.
    - [x] Add methodology map (recon → web/app → auth → container) and heuristic/LLM planner to pick next tools from findings.
    - [x] Maintain agent state (targets, ports, tech stack, findings, actions run) and expose `/plan` to show next steps.
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

- [ ] Add `supabash doctor` environment checks (binaries + config).
- [ ] Add plugin/tool registry (enable/disable tools in config).
- [ ] Add per-tool timeouts in config (e.g. `tools.nmap.timeout_seconds`).
- [ ] Make parallel tool results deterministic (stable ordering in reports).
- [ ] Include exact commands executed in reports (auditability).
- [ ] Add report schema versioning + validation.
- [ ] Add safety caps for aggressive mode (global rate limits).
- [ ] Add CI workflow to run unit tests automatically.
- [ ] Add packaging/release guide (pip/standalone binary).
- [ ] Improve Markdown report styling (anchors, tables, collapsible sections).
- [ ] Add explicit offline/no-LLM mode (graceful degradation).
- [ ] Add more opt-in integration targets beyond Juice Shop.
