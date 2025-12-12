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

- [ ] **LLM Client Setup**
    - [x] Integrate litellm client with provider/model selection from config.
    - [ ] (Optional) Add support for local models (Ollama/Mistral) for offline privacy.
- [x] **Prompt Engineering**
    - [x] Design the "Analyzer" prompt: Input = Tool Output -> Output = Vulnerability Summary.
    - [x] Design the "Planner" prompt: Input = Current State -> Output = Next Tool to run.
    - [x] Design the "Remediator" prompt: Input = Vulnerability -> Output = Code Fix.
- [ ] **Interactive Chat Interface**
    - [x] Implement `supabash chat` command with slash commands (/scan, /details, /report, /test).
    - [x] Add LLM-backed summary and remediation commands (/summary, /fix).
    - [ ] Enable the agent to ask clarifying questions to the user.
    - [ ] Chat workflow:
        - Single session as control plane; acknowledge and confirm scope before running tools.
        - Stream progress for long-running tools (checkpoints/heartbeats) and short summaries per tool; offer `/details <tool>` for full output.
        - Support slash commands (e.g., `/scan`, `/stop`, `/details`, `/report`, `/test`) without leaving chat.
        - Keep safety checks in-line: enforce allowed-hosts/rate limits; block out-of-scope requests.
        - Run tools/tests in background workers and stream output so chat stays responsive; allow resume if disconnected.
- [ ] **The "ReAct" Loop (Reason + Act)**
    - [ ] Implement the main agent loop:
        1.  Analyze Goal.
        2.  Select Tool.
        3.  Execute Tool.
        4.  Read Output.
        5.  Decide next step or Finish.
    - [x] Add methodology map (recon → web/app → auth → container) and heuristic/LLM planner to pick next tools from findings.
    - [x] Maintain agent state (targets, ports, tech stack, findings, actions run) and expose `/plan` to show next steps.
- [ ] **Context & Cost Management**
    - [ ] Implement a token limiter to ensure tool output doesn't crash the LLM context window (truncate large Nmap results).
    - [ ] Implement token usage tracking and cost estimation.
    - [ ] Implement basic prompt caching to save costs.

---

## 🛡️ Phase 4: Safety & Logic
*Goal: Ensure the agent behaves ethically and doesn't break things.*

- [ ] **Scope Control (CRITICAL)**
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
- [ ] **Code Fix Generator**
    - [ ] Ensure the AI provides specific code snippets (e.g., "Change line 40 in Dockerfile to...").

---

## 🧪 Phase 6: Testing & Polish
*Goal: Quality assurance.*

- [x] **Unit Testing**
    - [x] Test the parsers (Does the Nmap parser actually catch open ports?).
    - [x] Test the argument builders.
- [ ] **Integration Testing**
    - [ ] Spin up a deliberately vulnerable container (e.g., `dvwa` or `juiceshop`).
    - [ ] Run Supabash against it to verify it finds known issues.
- [ ] **Performance Tuning**
    - [ ] Optimize async execution (can we run Gobuster and Nmap at the same time?).

---

## 📚 Phase 7: Documentation
- [x] Write `README.md` (Done).
- [ ] Create a `CONTRIBUTING.md`.
- [ ] Document the tool requirements for users who don't use the installer.
