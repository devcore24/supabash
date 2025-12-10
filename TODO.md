# 📝 SupaBash Development Roadmap

This document outlines the step-by-step tasks required to build **SupaBash**, the AI-driven security audit agent.

---

## 🏗️ Phase 1: Foundation & Architecture
*Goal: Set up the project structure, dependency management, and installation scripts.*

- [ ] **Project Initialization**
    - [ ] Create git repository and standard folder structure (`/src`, `/tests`, `/docs`).
    - [ ] Create virtual environment setup (`python -m venv venv`).
    - [ ] Initialize `requirements.txt` (Typer, Rich, OpenAI, Subprocess, etc.).
    - [ ] **Logging System:** Implement file-based logging for debugging (rotational logs in `~/.supabash/logs`).
- [ ] **The "One-Command" Installer (`install.sh`)**
    - [ ] Write Bash script to detect OS (Debian/Ubuntu/Kali).
    - [ ] Implement `apt-get` logic for system binaries (nmap, nikto, sqlmap, etc.).
    - [ ] Add specific installation logic for external tools (Nuclei, Trivy).
    - [ ] Add Python dependency installation step.
    - [ ] Create the global entry point (symlink `supabash` to `/usr/local/bin`).
- [ ] **CLI Skeleton (Python)**
    - [ ] Set up `Typer` application entry point.
    - [ ] Design the ASCII Art Banner (The "Bashing" theme).
    - [ ] Create placeholder commands: `scan`, `audit`, `config`, `chat`.
- [ ] **Configuration Manager**
    - [ ] Create a config handler (YAML/JSON) to store API Keys and default settings.
    - [ ] Implement `supabash config` command to set keys interactively.

---

## 🛠️ Phase 2: The "Hands" (Tool Wrappers)
*Goal: Enable Python to execute Linux security binaries and capture their output.*

- [ ] **Command Execution Engine**
    - [ ] Create a `CommandRunner` class to handle `subprocess` calls safely.
    - [ ] Implement timeout handling (so Nmap doesn't hang forever).
    - [ ] Implement robust error handling and output decoding.
- [ ] **Recon Module Wrappers**
    - [ ] **Nmap:** Parse XML/Greppable output into JSON.
    - [ ] **Masscan/Rustscan:** Wrapper for high-speed port discovery.
    - [ ] **Tech Detection:** Integrate `WhatWeb` or simple HTTP header analysis.
- [ ] **Web Module Wrappers**
    - [ ] **Nikto:** Wrapper for server config scanning.
    - [ ] **Nuclei:** Wrapper for template-based scanning (Crucial for modern CVEs).
    - [ ] **Gobuster:** Wrapper for directory brute-forcing.
- [ ] **SQL & Auth Wrappers**
    - [ ] **Sqlmap:** Wrapper for automated SQL injection detection.
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
    - [ ] Run SupaBash against it to verify it finds known issues.
- [ ] **Performance Tuning**
    - [ ] Optimize async execution (can we run Gobuster and Nmap at the same time?).

---

## 📚 Phase 7: Documentation
- [ ] Write `README.md` (Done).
- [ ] Create a `CONTRIBUTING.md`.
- [ ] Document the tool requirements for users who don't use the installer.