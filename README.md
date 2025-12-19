
# Supabash

```text
   _____                   _               _     
  / ____|                 | |             | |    
 | (___  _   _ _ __   __ _| |__   __ _ ___| |__  
  \___ \| | | | '_ \ / _` | '_ \ / _` / __| '_ \ 
  ____) | |_| | |_) | (_| | |_) | (_| \__ \ | | |
 |_____/ \__,_| .__/ \__,_|_.__/ \__,_|___/_| |_|
              | |                                
              |_|                                
```

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-AGPLv3-blue)
![Status](https://img.shields.io/badge/Status-Beta-orange)

> **⚠️ Development Status:** This project is currently in **Active Development (Phase 8)**. The CLI, core tool wrappers, chat control plane, audit reporting (JSON/Markdown), and LLM-based summary/remediation are implemented; remaining work focuses on hardening, configurability, and expanding the toolchain.  
> Progress: `[███████████████████▉]` **99%**

**Supabash** is an autonomous AI Security Agent designed for developers, pentesters, DevOps engineers, Red and Blue Teams who want to **automate security audits** without sacrificing depth or understanding. Unlike traditional wrapper scripts, Supabash acts as a **reasoning engine**: it intelligently orchestrates industry-standard security tools, analyzes their output in real-time, identifies security holes, and writes detailed audit reports with actionable remediation steps.


---

## 🚀 Key Features

*   **🤖 Autonomous Reasoning (Beta):** The agent can plan next steps based on scan results (ReAct Pattern).
*   **🛡️ Auditing:** Scans infrastructure, web applications, and Docker container images (wireless is planned).
*   **📝 Smart Reporting:** Generates human-readable audits containing detection details, severity levels, and **code-level fix suggestions**.
*   **⚡ High-Performance:** Orchestrates fast scanners (Rust/Go) alongside deep-dive frameworks (Python/Ruby).
*   **🔌 Extensible Design:** Modular wrappers today; plugin registry planned.

---

## 🛠️ The Arsenal (Planned Toolset)

Supabash aims to orchestrate the following tools over time (not all wrappers are implemented yet). For what currently works today, see **Implemented Wrappers (Beta)** below.

### 🔍 Recon & Discovery
*   **Nmap** (Network mapping & service detection)
*   **Masscan** (High-speed port scanning)
*   **Rustscan** (Modern, fast port scanner)
*   **subfinder** (Subdomain discovery)
*   **httpx** (HTTP probing / alive endpoints)
*   **Netdiscover** (ARP reconnaissance)
*   **Dnsenum** (DNS enumeration)
*   **Sslscan** (SSL/TLS analysis)
*   **Enum4linux-ng** (SMB/Samba enumeration)

### 🌐 Web & Exploit
*   **Metasploit Framework** (Exploitation & validation)
*   **Sqlmap** (Automated SQL injection)
*   **Gobuster** (Directory & file brute-forcing)
*   **ffuf** (Fast content discovery / fuzzing)
*   **katana** (Crawling / spidering)
*   **Nikto** (Web server scanning)
*   **WPScan** (WordPress security scanner)
*   **Nuclei** (Template-based vulnerability scanning)
*   **Searchsploit** (Offline exploit database)

### 🔐 Credentials & Access
*   **Hashcat** (Advanced password recovery)
*   **John the Ripper** (Password cracker)
*   **Hydra** (Online login brute-forcer)
*   **Medusa** (Parallel network login brute-forcer)
*   **CrackMapExec** (Post-exploitation for AD)
*   **Impacket Suite** (Network protocols & packet manipulation)

### 📡 Wireless
*   **Aircrack-ng Suite** (WiFi security auditing)
*   **Reaver** (WPS attack tool)
*   **Bettercap** (MITM & network utility)
*   **Wifite** (Automated wireless auditor)
*   **Hostapd** (Rogue AP creation)

### 🕵️ Intel & OSINT
*   **TheHarvester** (E-mail, subdomain & name harvesting)
*   **Recon-ng** (Web reconnaissance framework)
*   **Shodan CLI** (IoT search engine)
*   **Tcpdump** (Packet analyzer)
*   **Wireshark** (Network protocol analyzer)

### 📉 Stress & Performance
*   **Hping3** (Packet generator/analyzer)
*   **Iperf3** (Network bandwidth measurement)
*   **ApacheBench (ab)** (HTTP server benchmarking)
*   **Tc/Netem** (Network emulation)

### 🔧 Utilities & Post-Exploitation
*   **SSH / Socat / Netcat** (Connectivity & redirection)
*   **Mimikatz** (Windows credential extraction helpers)
*   **Loot Manager** (Automated evidence collection)

---

## 📥 Installation

Supabash requires **Linux** (Kali, Ubuntu, Debian) or **WSL2**.

### One-Command Setup
We provide a bootstrap script to install Python dependencies and system binaries automatically.

```bash
git clone https://github.com/yourusername/supabash.git
cd supabash
chmod +x install.sh
sudo ./install.sh
```

Notes:
- The installer can update **Nuclei templates** for your (non-root) user after installing `nuclei` (recommended). Disable with `SUPABASH_UPDATE_NUCLEI_TEMPLATES=0 sudo ./install.sh`.
- If Nuclei ever fails due to missing templates, run `nuclei -update-templates`.

### Optional: PDF/HTML Report Export (WeasyPrint)

If you want Supabash to export reports to **HTML/PDF** (in addition to JSON/Markdown), you’ll need extra dependencies.

- **System libraries (Ubuntu/Debian):**
  - `libcairo2`, `libpango-1.0-0`, `libpangocairo-1.0-0`, `libpangoft2-1.0-0`, `libgdk-pixbuf-2.0-0`, `shared-mime-info`, `fonts-dejavu-core`
- **Python packages (installed into the project venv, not system Python):**
  - `weasyprint`, `markdown`

Installer support:
- Interactive install: run `sudo ./install.sh` and answer **yes** to the optional PDF prompt
- Non-interactive: `SUPABASH_PDF_EXPORT=1 sudo ./install.sh`

Enable exports:
- Set `core.report_exports.html=true` and/or `core.report_exports.pdf=true` in `config.yaml`

### Quick Environment Check
```bash
supabash doctor
supabash doctor --json
```

### Manual Installation
1.  Install system dependencies:
    - Quick list: `requirements_system.txt`
    - Full manual guide (APT): `docs/system-requirements.md`
2.  Install Python libraries:
    ```bash
    pip3 install -r requirements.txt
```

## 🧪 Integration Testing (Optional)

- Docker-based harness: `docker-compose.integration.yml`
- Guide: `docs/integration-testing.md`
  - Targets: OWASP Juice Shop (`:3000`) + DVWA (`:3001`)

Enable the opt-in integration tests (skipped unless `SUPABASH_INTEGRATION=1`):
```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_dvwa -q
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_juiceshop -q
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest discover -s tests -q
```

---

## 💻 Usage

Once installed, the `supabash` command is available globally.

### 1. Basic Recon Scan
Launch a basic recon scan against a target.
```bash
# Ensure the target is listed in core.allowed_hosts in config.yaml (recommended),
# or pass --force to bypass the scope check.
supabash scan 192.168.1.10 --yes
```
Note: when running without `sudo`, Supabash will automatically skip Nmap root-only flags (like `-O` OS detection) and fall back to non-root-safe scans.

### 2. Full Application Audit
Run a comprehensive audit including recon, web scanning, and optional container scanning, then generate a report.
```bash
# Ensure the target is listed in core.allowed_hosts in config.yaml (recommended),
# or pass --force to bypass the scope check.
supabash audit 192.168.1.10 --yes
# include container image scan
supabash audit 192.168.1.10 --container-image my-app:latest --yes
# write markdown report too
supabash audit 192.168.1.10 --yes --output reports/my-audit.json   # also writes reports/my-audit.md
# run web tools in parallel (and overlap with recon when a URL is provided)
supabash audit "http://192.168.1.10" --yes --parallel-web --max-workers 3
# run sqlmap only when providing a parameterized URL
supabash audit "http://192.168.1.10/?id=1" --yes
# generate LLM remediation steps + code samples (costs tokens)
supabash audit 192.168.1.10 --yes --remediate --max-remediations 5 --min-remediation-severity HIGH
# opt-in: run nikto too (slow)
supabash audit "http://192.168.1.10" --yes --nikto
# opt-in: credential bruteforce (high impact/noisy; requires explicit authorization + wordlists)
supabash audit 192.168.1.10 --yes --hydra --hydra-services ssh --hydra-usernames users.txt --hydra-passwords passwords.txt
```
Note: by default Supabash writes `reports/report-YYYYmmdd-HHMMSS.json` and `reports/report-YYYYmmdd-HHMMSS.md`. Avoid running `supabash audit` with `sudo` unless you need root-only scan modes; otherwise your report files may be owned by root.
If web tools show `Executable not found`, install system requirements via `install.sh` or `docs/system-requirements.md`.

### 2b. AI Audit (Baseline + Agentic Expansion)
AI audit combines the deterministic `audit` pipeline with a bounded expansion phase (useful when Nmap finds multiple web ports). It produces one unified report.
```bash
supabash ai-audit 192.168.1.10 --yes
supabash audit 192.168.1.10 --agentic --yes   # alias
supabash ai-audit "http://192.168.1.10" --yes --llm-plan --max-actions 8
```
Note: AI audit writes `reports/ai-audit-YYYYmmdd-HHMMSS.json` and `reports/ai-audit-YYYYmmdd-HHMMSS.md` by default (and exits non-zero if `--llm-plan` planning fails).

### 2c. ReAct Loop (Plan → Act)
Run an iterative ReAct loop that plans next tools based on recon results.
```bash
supabash react 192.168.1.10 --yes --max-actions 10
supabash react "http://192.168.1.10" --yes --remediate
supabash react 192.168.1.10 --output reports/my-react.json --yes
supabash react localhost --yes --status-file reports/react_status.json
supabash react localhost --yes --llm-plan   # LLM-driven planning (requires configured provider/key)
# opt-in: allow planned hydra steps to execute (requires explicit authorization + wordlists)
supabash react 192.168.1.10 --yes --hydra --hydra-usernames users.txt --hydra-passwords passwords.txt
```
Note: ReAct writes `reports/react-YYYYmmdd-HHMMSS.json` and `reports/react-YYYYmmdd-HHMMSS.md` by default.

### 3. Container Image Scan
Scan a local Docker image for CVEs and configuration issues (via Trivy).
```bash
supabash audit 127.0.0.1 --container-image my-app:latest --yes
```

### 4. Interactive Mode
Talk to the agent directly to plan a custom engagement (slash commands supported).
```bash
supabash chat
# inside chat:
/scan 192.168.1.10 --profile fast --scanner nmap  # add --allow-public only if authorized
/scan 192.168.1.10 --profile fast --scanner nmap --bg
/audit 192.168.1.10 --mode normal --remediate  # writes reports/report-YYYYmmdd-HHMMSS.json + .md
/audit 192.168.1.10 --mode normal --output reports/custom.json --remediate
/audit 192.168.1.10 --mode normal --nikto --remediate --bg
/audit "http://192.168.1.10" --mode normal --parallel-web --max-workers 3 --bg
/audit target=localhost   # also accepted
/status
/status --watch --interval 1 --verbose
/stop   # sends a cancel request; running tool processes are terminated (best-effort)
/clear-state
/details      # show last scan
/details nuclei  # show per-tool output from last audit
/report out.json
/test         # run unit tests
/summary      # LLM summary (requires configured provider/key)
/fix "SQL Injection" "param id injectable"  # LLM remediation
/plan         # heuristic next steps
# freeform text (no auto-scans): the agent asks clarifying questions and suggests next commands
I want to audit my staging app for common web vulns
```

Chat memory & context awareness:
- Chat state is persisted to `.supabash/chat_state.json` (last results + message history + rolling summary).
- Freeform chat may propose a slash command; type `y/yes` to run the proposed command.
- LLM calls print token/cost metadata plus a best-effort context-window estimate (e.g. `context≈1200/8192 (14.6%)`).
- Secrets (API keys/tokens/passwords) are redacted from saved chat history.

---

## 📜 CLI Reference (Commands + Params)

This is a quick, readable snapshot of the current CLI surface area. For the authoritative help (kept in sync with the code), run:
```bash
supabash --help
supabash <command> --help
```

<details>
<summary><strong>scan</strong> — Basic recon scan</summary>

```bash
supabash scan [OPTIONS] TARGET
```

- Arguments: `TARGET` (required)
- Options:
  - `--profile`, `-p` (default: `fast`) — `fast|full|stealth`
  - `--scanner`, `-s` (default: `nmap`) — `nmap|masscan|rustscan`
  - `--force` — bypass allowed-hosts check
  - `--allow-public` — allow public IP targets (authorized only)
  - `--yes` — skip consent prompt
  - `--masscan-rate` — override masscan packets/sec (pps)
  - `--rustscan-batch` — override rustscan batch size
</details>

<details>
<summary><strong>audit</strong> — Full audit pipeline + report</summary>

```bash
supabash audit [OPTIONS] TARGET
```

- Arguments: `TARGET` (required) — IP / hostname / URL / container ID
- Options:
  - `--output`, `-o` — output JSON path (default: `reports/report-YYYYmmdd-HHMMSS.json`)
  - `--markdown`, `-m` — output Markdown path (default: derived from `--output`)
  - `--container-image`, `-c` — optional container image to scan with Trivy
  - `--force` — bypass allowed-hosts check
  - `--allow-public` — allow public IP targets (authorized only)
  - `--yes` — skip consent prompt
  - `--mode` (default: `normal`) — `normal|stealth|aggressive`
  - `--nuclei-rate` (default: `0`) — nuclei rate-limit (requests/sec)
  - `--gobuster-threads` (default: `10`) — gobuster threads
  - `--gobuster-wordlist` — gobuster wordlist path
  - `--parallel-web` — run web tools in parallel (URL targets can overlap recon)
  - `--max-workers` (default: `3`) — max workers for `--parallel-web`
  - `--nikto` — opt-in nikto scan (slow/noisy)
  - `--hydra` — opt-in bruteforce (requires explicit wordlists + authorization)
  - `--hydra-usernames` — usernames file or single username
  - `--hydra-passwords` — passwords file or single password
  - `--hydra-services` (default: `ssh,ftp`) — comma-separated services
  - `--hydra-threads` (default: `4`) — hydra `-t` parallel tasks
  - `--hydra-options` — extra hydra CLI options (advanced)
  - `--remediate` — LLM remediation (steps + code snippets)
  - `--no-llm` — disable LLM for this run
  - `--agentic`, `--react` — agentic audit mode (baseline + bounded expansion)
  - `--llm-plan` — LLM plans agentic expansion steps (only with `--agentic`)
  - `--max-actions` (default: `10`) — cap agentic expansion length (only with `--agentic`)
  - `--max-remediations` (default: `5`) — cost control
  - `--min-remediation-severity` (default: `MEDIUM`) — `CRITICAL|HIGH|MEDIUM|LOW|INFO`
</details>

<details>
<summary><strong>ai-audit</strong> — Agentic audit (alias for audit --agentic)</summary>

```bash
supabash ai-audit [OPTIONS] TARGET
```

- Arguments: `TARGET` (required) — IP / hostname / URL / container ID
- Options: same as `audit`, plus:
  - default output is `reports/ai-audit-YYYYmmdd-HHMMSS.json` (+ `.md`)
  - `--llm-plan` — LLM plans agentic expansion steps (fails run if planning fails)
  - `--max-actions` (default: `10`) — cap agentic expansion length
</details>

<details>
<summary><strong>react</strong> — ReAct loop (plan → act → summarize)</summary>

```bash
supabash react [OPTIONS] TARGET
```

- Arguments: `TARGET` (required) — IP / hostname / URL
- Options:
  - `--output`, `-o` — output JSON path (default: `reports/react-YYYYmmdd-HHMMSS.json`)
  - `--markdown`, `-m` — output Markdown path (default: derived from `--output`)
  - `--status/--no-status` (default: `--status`) — print live progress
  - `--status-file` — write JSON status updates while running
  - `--llm-plan` — LLM plans next actions iteratively (fails run if planning fails)
  - `--no-llm` — disable LLM for this run
  - `--force` — bypass allowed-hosts check
  - `--allow-public` — allow public IP targets (authorized only)
  - `--yes` — skip consent prompt
  - `--mode` (default: `normal`) — `normal|stealth|aggressive`
  - `--nuclei-rate` (default: `0`) — nuclei rate-limit (requests/sec)
  - `--gobuster-threads` (default: `10`) — gobuster threads
  - `--gobuster-wordlist` — gobuster wordlist path
  - `--hydra` — opt-in bruteforce (requires explicit wordlists + authorization)
  - `--hydra-usernames` — usernames file or single username
  - `--hydra-passwords` — passwords file or single password
  - `--hydra-services` (default: `ssh,ftp`) — comma-separated services
  - `--hydra-threads` (default: `4`) — hydra `-t` parallel tasks
  - `--hydra-options` — extra hydra CLI options (advanced)
  - `--remediate` — LLM remediation (steps + code snippets)
  - `--max-remediations` (default: `5`) — cost control
  - `--min-remediation-severity` (default: `MEDIUM`) — `CRITICAL|HIGH|MEDIUM|LOW|INFO`
  - `--max-actions` (default: `10`) — cap the loop length
</details>

<details>
<summary><strong>chat</strong> — Interactive chat control plane</summary>

```bash
supabash chat
```
</details>

<details>
<summary><strong>doctor</strong> — Environment readiness checks</summary>

```bash
supabash doctor [--json] [--verbose]
```
</details>

<details>
<summary><strong>config</strong> — Configure provider, scope, consent</summary>

```bash
supabash config [OPTIONS]
```

- Options:
  - `--provider`, `-p` — active LLM provider (e.g. `openai|ollama|lmstudio`)
  - `--key`, `-k` — API key for the selected/active provider
  - `--model`, `-m` — model for the selected/active provider
  - `--api-base` — API base URL (OpenAI-compatible backends)
  - `--allow-host` — add an allowed host/IP/CIDR entry
  - `--remove-host` — remove an allowed host/IP/CIDR entry
  - `--list-allowed-hosts` — show allowed hosts
  - `--accept-consent` — persist `core.consent_accepted=true`
  - `--reset-consent` — set `core.consent_accepted=false`
  - `--allow-public-ips/--no-allow-public-ips` — toggle public-IP guardrail
</details>

### Scanner Engine Selection
Choose your recon engine with `--scanner`:
```bash
supabash scan 192.168.1.10 --scanner nmap     # default
supabash scan 192.168.1.10 --scanner masscan # fast sweep
supabash scan 192.168.1.10 --scanner rustscan # rustscan+nmap greppable output
# tuning for speed/stealth (masscan/rustscan)
supabash scan 192.168.1.10 --scanner masscan --profile full --masscan-rate 2000
supabash scan 192.168.1.10 --scanner rustscan --profile stealth --rustscan-batch 500
```

---

## ⚙️ Configuration

- Default config lives in the project root as `config.yaml` (falls back to `~/.supabash/config.yaml`).
- Control verbosity via `core.log_level` (`INFO`, `DEBUG`, etc.); logs are written to `~/.supabash/logs/debug.log`.
- Enable/disable tools globally via `tools.<tool>.enabled` (see `config.yaml.example`).
- Set per-tool timeouts via `tools.<tool>.timeout_seconds` (0 disables the timeout).
- Offline/no-LLM mode: set `llm.enabled=false` in `config.yaml` or pass `--no-llm` on `audit`/`ai-audit`/`react`.
- Local-only LLM mode (privacy): set `llm.local_only=true` to allow only `ollama`/`lmstudio` providers.
- Restrict scope via `core.allowed_hosts` (IPs/hosts/CIDRs/wildcards like `*.corp.local`); add your own infra there. Use `--force` on `scan`/`audit` to bypass.
- Public IP guardrail: IP-literal public targets are blocked by default; enable with `core.allow_public_ips=true`, `supabash config --allow-public-ips`, or per-run `--allow-public` (only if authorized).
- Edit allowed hosts via CLI: `supabash config --allow-host 10.0.0.0/24`, `supabash config --remove-host 10.0.0.0/24`, `supabash config --list-allowed-hosts`.
- Manage providers, API keys, and models with `supabash config`.
- Local models (Ollama): `supabash config --provider ollama --model ollama/llama3.1 --api-base http://localhost:11434` (no API key required).
- Local models (LM Studio): `supabash config --provider lmstudio --model local-model --api-base http://localhost:1234/v1` (no API key required; uses OpenAI-compatible API).
- Manage scan safety: consent prompts are remembered in `core.consent_accepted` after the first interactive acceptance (use `supabash config --reset-consent` to re-prompt); `--yes` skips prompting for a single run.
- LLM context/cost controls: set `llm.max_input_chars` to cap tool output sent to the LLM; LLM token usage + estimated USD cost are recorded in audit reports.
- Chat memory controls: `chat.llm_history_turns`, `chat.summary_every_turns`, `chat.history_max_messages`. For local models, set `llm.max_input_tokens` if you want accurate context % reporting.
- LLM caching (optional): enable with `llm.cache_enabled=true` (and optionally set `llm.cache_ttl_seconds`, `llm.cache_max_entries`, `llm.cache_dir`) to reuse identical LLM responses and reduce cost.
- LLM payload + caching knobs (advanced):
  - `llm.max_input_chars` — hard cap (characters) on what gets sent to the LLM per request (higher = more context/cost).
  - `llm.max_input_tokens` — fallback token window size used only for showing chat “context %” when the model limit can’t be detected (common for local servers); `0` disables the fallback.
  - `llm.cache_enabled` — enable/disable caching of identical LLM calls.
  - `llm.cache_ttl_seconds` / `llm.cache_max_entries` — cache retention controls (time-to-live and max number of entries).
- Tune web tooling: `supabash audit ... --nuclei-rate 10 --gobuster-threads 20` (and optionally `--gobuster-wordlist /path/to/list`).
- Parallelize web tools: `supabash audit ... --parallel-web --max-workers 3` (URL targets can overlap recon with web tooling).
- Safety caps (aggressive mode): Supabash enforces global caps (rate limits / concurrency) in `--mode aggressive`; configure via `core.aggressive_caps` in `config.yaml`.

---

## ✅ Implemented Wrappers (Beta)
- **Audit pipeline (runs by default):** Nmap → httpx → WhatWeb → Nuclei → Gobuster (+ conditional Dnsenum/sslscan/enum4linux-ng, and optional Sqlmap/Supabase RLS/Trivy)
- **AI audit (agentic):** `supabash ai-audit ...` (or `supabash audit --agentic ...`) runs the baseline audit + a bounded expansion phase and writes one unified report.
- **Recon engines (scan mode):** Nmap, Masscan, Rustscan
- **Wrappers implemented:** Nikto (opt-in via `--nikto`), Hydra (opt-in via `--hydra` + explicit wordlists)
- **Optional additions (opt-in):** `ffuf` fallback for content discovery when Gobuster fails (`tools.ffuf.enabled=true`); `katana` crawl/spider for endpoint expansion (`tools.katana.enabled=true`); `subfinder` subdomain discovery (`tools.subfinder.enabled=true`); `searchsploit` offline exploit references derived from service fingerprints (`tools.searchsploit.enabled=true`)
- **LLM integration:** litellm-based client with config-driven provider/model selection
- **Chat mode:** slash commands `/scan`, `/audit`, `/status`, `/stop`, `/details`, `/report`, `/test`, `/summary`, `/fix`, `/plan`, `/clear-state`
- **Reporting:** timestamped JSON + Markdown reports under `reports/` (includes exact commands executed for auditability)
- **Report schema:** JSON reports include `schema_version` + `schema_validation` for sanity checks and forward compatibility
- **Markdown reports:** include TOC + summary tables for readability

---

## 📊 Example Audit Output

When Supabash detects an issue, it provides context and solutions:

```json
{
  "severity": "HIGH",
  "type": "SQL Injection",
  "tool": "sqlmap",
  "endpoint": "/login.php?user=",
  "analysis": "The parameter 'user' is vulnerable to boolean-based blind SQLi.",
  "remediation_hint": "Use prepared statements in PHP (PDO). Do not concatenate user input directly into SQL strings.",
  "code_fix_example": "$stmt = $pdo->prepare('SELECT * FROM users WHERE user = :user');"
}
```

---

## ⚠️ Legal Disclaimer

**Supabash is for educational purposes and authorized security auditing only.**

Usage of Supabash for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 📄 License

Supabash is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See `LICENSE`.

---

## 🤝 Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

CI runs unit tests automatically via GitHub Actions (`.github/workflows/ci.yml`).

Release/packaging guide: `docs/release.md`.

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request
