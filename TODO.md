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

---

## 🛠️ Phase 2: The "Hands" (Tool Wrappers)
*Goal: Enable Python to execute Linux security binaries and capture their output.*

- [x] **Command Execution Engine**
    - [x] Create a `CommandRunner` class to handle `subprocess` calls safely.
    - [x] Implement timeout handling (so Nmap doesn't hang forever).
    - [x] Implement robust error handling and output decoding.
- [ ] **Recon Module Wrappers**
    - [x] **Nmap:** Parse XML/Greppable output into JSON.
    - [x] **Masscan/Rustscan:** Wrapper for high-speed port discovery.
        - [x] Masscan wrapper with list-output parser.
        - [x] Rustscan wrapper with greppable parser.
    - [x] **CLI Integration:** Allow selecting Nmap/Masscan/Rustscan via `--scanner`.
    - [x] **Tech Detection:** Integrate `WhatWeb` or simple HTTP header analysis.
- [ ] **Web Module Wrappers**
    - [x] **Nikto:** Wrapper for server config scanning.
    - [x] **Nuclei:** Wrapper for template-based scanning (Crucial for modern CVEs).
    - [x] **Gobuster:** Wrapper for directory brute-forcing.
- [ ] **SQL & Auth Wrappers**
    - [x] **Sqlmap:** Wrapper for automated SQL injection detection.
    - [ ] **Hydra:** Wrapper for service authentication brute-forcing.
- [ ] **Container Module**
    - [ ] **Trivy:** Wrapper to scan local Docker images.
- [ ] **Supabase Specific Module**
    - [ ] Implement the RLS (Row Level Security) checker for Supabase URLs.
- [ ] **Wireless Module (Experimental)**
    - [ ] **Aircrack-ng:** Basic wrapper for monitoring and capturing (requires hardware access).

---

## 🧠 Phase 3: The "Brain" (AI Integration)
*Goal: Connect the tools to the LLM so it can reason about the results.*

- [ ] **LLM Client Setup**
    - [ ] Integrate OpenAI API client.
    - [ ] (Optional) Add support for local models (Ollama/Mistral) for offline privacy.
- [ ] **Prompt Engineering**
    - [ ] Design the "Analyzer" prompt: Input = Tool Output -> Output = Vulnerability Summary.
    - [ ] Design the "Planner" prompt: Input = Current State -> Output = Next Tool to run.
    - [ ] Design the "Remediator" prompt: Input = Vulnerability -> Output = Code Fix.
- [ ] **Interactive Chat Interface**
    - [ ] Implement `supabash chat` command for conversational planning.
    - [ ] Enable the agent to ask clarifying questions to the user.
- [ ] **The "ReAct" Loop (Reason + Act)**
    - [ ] Implement the main agent loop:
        1.  Analyze Goal.
        2.  Select Tool.
        3.  Execute Tool.
        4.  Read Output.
        5.  Decide next step or Finish.
- [ ] **Context & Cost Management**
    - [ ] Implement a token limiter to ensure tool output doesn't crash the LLM context window (truncate large Nmap results).
    - [ ] Implement token usage tracking and cost estimation.
    - [ ] Implement basic prompt caching to save costs.

---

## 🛡️ Phase 4: Safety & Logic
*Goal: Ensure the agent behaves ethically and doesn't break things.*

- [ ] **Scope Control (CRITICAL)**
    - [ ] Implement a strict "Allowed Hosts" check.
    - [ ] Prevent the agent from scanning unverified public IPs.
- [ ] **Legal & Consent**
    - [ ] Implement mandatory disclaimer/consent prompt on first run.
- [ ] **Traffic Control**
    - [ ] Add flags for "Stealth Mode" vs "Aggressive Mode".
    - [ ] Implement rate limiting options.

---

## 📊 Phase 5: Reporting & Audit
*Goal: Turn scan data into a valuable document for developers.*

- [ ] **Data Aggregation**
    - [ ] Create a standard JSON schema for findings (Severity, Description, Evidence, Fix).
- [ ] **Report Generators**
    - [ ] **JSON Report:** For machine integration.
    - [ ] **Markdown Report:** A pretty, readable audit file with sections.
- [ ] **Code Fix Generator**
    - [ ] Ensure the AI provides specific code snippets (e.g., "Change line 40 in Dockerfile to...").

---

## 🧪 Phase 6: Testing & Polish
*Goal: Quality assurance.*

- [ ] **Unit Testing**
    - [ ] Test the parsers (Does the Nmap parser actually catch open ports?).
    - [ ] Test the argument builders.
- [ ] **Integration Testing**
    - [ ] Spin up a deliberately vulnerable container (e.g., `dvwa` or `juiceshop`).
    - [ ] Run Supabash against it to verify it finds known issues.
- [ ] **Performance Tuning**
    - [ ] Optimize async execution (can we run Gobuster and Nmap at the same time?).

---

## 📚 Phase 7: Documentation
- [ ] Write `README.md` (Done).
- [ ] Create a `CONTRIBUTING.md`.
- [ ] Document the tool requirements for users who don't use the installer.
