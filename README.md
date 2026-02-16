
# Supabash
<img src="docs/images/supabash_mouse_mascot_transparentbg_200x227.png" alt="Supabash mascot" width="180" align="left" />

```text

   _____                   _               _     
  / ____|                 | |             | |    
 | (___  _   _ _ __   __ _| |__   __ _ ___| |__  
  \___ \| | | | '_ \ / _` | '_ \ / _` / __| '_ \ 
  ____) | |_| | |_) | (_| | |_) | (_| \__ \ | | |
 |_____/ \__,_| .__/ \__,_|_.__/ \__,_|___/_| |_|
              | |     AGENTIC   AI   AUDIT                         
              |_|      
```

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-AGPLv3-blue)
![Status](https://img.shields.io/badge/Status-Beta-orange)

> **⚠️ Development Status:** Supabash is in active development. Core CLI and baseline audit workflows are production-usable, while some agentic planning paths, cloud posture checks, and Supabase heuristics remain **beta**. Coverage is improving and behavior may change as reliability and compliance mapping mature.  
> **Status:** **Beta (stabilization + coverage expansion in progress)**

**Supabash** is an agentic AI security audit tool that generates evidence-backed **Supabash Audit** reports.  
It can also be used to prepare for compliance assessments and certifications such as **SOC 2 / ISO 27001 / PCI DSS / DORA / NIS2 / GDPR / BSI**.

Example: [reports](example_reports/)

Requirements:
Supabash requires Linux (Kali, Ubuntu, Debian) or WSL2.  
macOS: manual/experimental setup only, untested.  



---

## 🚀 Key Features

*   **🤖 Autonomous Reasoning (Beta):** Iterative tool-calling planning proposes one best-next action at a time, critiques outcome signal, and replans.
*   **🛡️ Assessment Coverage:** Infrastructure, web apps, containers, and wireless (experimental) with scope controls.
*   **📋 Compliance-Mapped:** Optional compliance profiles (PCI, SOC2, ISO 27001, DORA, NIS2, GDPR, BSI) tune tool settings and annotate findings with control references for readiness.
*   **📝 Assessment Reporting + Evidence Packs:** Structured JSON/Markdown/HTML/PDF outputs with severity, evidence, compliance coverage matrix, and recommended next actions.
*   **📉 Signal Economy Controls:** Repeat-policy filtering + diminishing-returns stopping reduce redundant low-yield agentic actions.
*   **⚡ Performance:** Combines fast scanners (Rust/Go) with deep-dive frameworks (Python/Ruby).
*   **🔌 Extensible Design:** Modular wrappers with a configurable tool registry (plugins planned).

---

## 🛠️ The Arsenal (Toolset)

Supabash orchestrates the following security tools. **27 wrappers are currently implemented** (✅). Planned tools are marked with 🔜.

### 🔍 Recon & Discovery
*   ✅ **Nmap** (Network mapping & service detection)
*   ✅ **Masscan** (High-speed port scanning)
*   ✅ **Rustscan** (Modern, fast port scanner)
*   ✅ **subfinder** (Subdomain discovery)
*   ✅ **httpx** (HTTP probing / alive endpoints)
*   ✅ **Netdiscover** (ARP reconnaissance)
*   ✅ **Dnsenum** (DNS enumeration)
*   ✅ **Sslscan** (SSL/TLS analysis)
*   ✅ **Enum4linux-ng** (SMB/Samba enumeration)

### 🌐 Web & Exploit
*   🔜 **Metasploit Framework** (Exploitation & validation)
*   ✅ **Sqlmap** (Automated SQL injection)
*   ✅ **Gobuster** (Directory & file brute-forcing)
*   ✅ **ffuf** (Fast content discovery / fuzzing)
*   ✅ **katana** (Crawling / spidering)
*   ✅ **Nikto** (Web server scanning)
*   ✅ **WPScan** (WordPress security scanner)
*   ✅ **Nuclei** (Template-based vulnerability scanning)
*   ✅ **Searchsploit** (Offline exploit database)

### 🔐 Credentials & Access
*   🔜 **Hashcat** (Advanced password recovery)
*   🔜 **John the Ripper** (Password cracker)
*   ✅ **Hydra** (Online login brute-forcer)
*   ✅ **Medusa** (Parallel network login brute-forcer)
*   ✅ **CrackMapExec/NetExec** (Post-exploitation for AD)
*   🔜 **Impacket Suite** (Network protocols & packet manipulation)

### 📡 Wireless
*   ✅ **Aircrack-ng Suite** (WiFi security assessment)
*   🔜 **Reaver** (WPS attack tool)
*   🔜 **Bettercap** (MITM & network utility)
*   🔜 **Wifite** (Automated wireless assessment)
*   🔜 **Hostapd** (Rogue AP creation)

### 🕵️ Intel & OSINT
*   ✅ **TheHarvester** (E-mail, subdomain & name harvesting)
*   🔜 **Recon-ng** (Web reconnaissance framework)
*   🔜 **Shodan CLI** (IoT search engine)
*   🔜 **Tcpdump** (Packet analyzer)
*   🔜 **Wireshark** (Network protocol analyzer)

### 📉 Stress & Performance
*   🔜 **Hping3** (Packet generator/analyzer)
*   🔜 **Iperf3** (Network bandwidth measurement)
*   🔜 **ApacheBench (ab)** (HTTP server benchmarking)
*   🔜 **Tc/Netem** (Network emulation)

### 🔧 Utilities & Post-Exploitation
*   🔜 **SSH / Socat / Netcat** (Connectivity & redirection)
*   🔜 **Mimikatz** (Windows credential extraction helpers)
*   🔜 **Loot Manager** (Automated evidence collection)

### 📦 Container & Cloud
*   ✅ **ScoutSuite** (Multi-cloud posture assessment — **beta coverage, not exhaustive**)
*   ✅ **Prowler** (AWS security best-practice checks — **beta coverage, not exhaustive**)
*   ✅ **Trivy** (Container image CVE scanning)
*   ✅ **Supabase Audit** (RLS, URL/key/RPC exposure checks — **beta heuristics, not exhaustive**)
*   🔜 **Firebase Audit** (rules misconfig, public buckets, exposed keys)

---

## 📥 Installation

Supabash requires **Linux** (Kali, Ubuntu, Debian) or **WSL2**.

### Quick Setup
We provide a bootstrap script to install Python dependencies and system binaries automatically.

```bash
git clone https://github.com/yourusername/supabash.git
cd supabash
chmod +x install.sh
sudo ./install.sh
```

or

```bash
git clone https://github.com/yourusername/supabash.git && cd supabash && chmod +x install.sh && sudo ./install.sh
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
supabash doctor --verbose
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
  - Targets: OWASP Juice Shop (`:3002`) + DVWA (`:3001`) + Supabase mock (`:4001`)

Enable the opt-in integration tests (skipped unless `SUPABASH_INTEGRATION=1`):
```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_dvwa -q
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_juiceshop -q
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_supabase -q
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest discover -s tests -q
```

---

## 🧭 AI Audit Workflow

For a clear breakdown of how `ai-audit` selects tools and produces its final report:
- [AI Audit Workflow](docs/ai-audit-workflow.md)

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
# opt-in: medusa bruteforce (defaults module/port from nmap)
supabash audit 192.168.1.10 --yes --medusa --medusa-usernames users.txt --medusa-passwords passwords.txt
# opt-in: CrackMapExec/NetExec (with creds or explicit args)
supabash audit 192.168.1.10 --yes --crackmapexec --cme-username admin --cme-password secret --cme-protocol smb --cme-enum shares,users
# opt-in: OSINT (domain targets only)
supabash audit example.com --yes --theharvester --theharvester-sources crtsh,otx
# opt-in: LAN discovery (private CIDR; requires sudo)
sudo supabash audit 192.168.1.10 --yes --netdiscover --netdiscover-range 192.168.1.0/24
# opt-in: WiFi capture (requires monitor mode; use --aircrack-airmon to auto toggle)
sudo supabash audit 192.168.1.10 --yes --aircrack --aircrack-interface wlan0mon
# opt-in: cloud posture checks (requires cloud credentials)
supabash audit 192.168.1.10 --yes --scoutsuite --scoutsuite-provider aws
supabash audit 192.168.1.10 --yes --prowler
```
Note: Supabash writes JSON + Markdown by default; HTML/PDF exports are optional via `core.report_exports`. Avoid running `supabash audit` with `sudo` unless you need root-only scan modes; otherwise your report files may be owned by root.
If web tools show `Executable not found`, install system requirements via `install.sh` or `docs/system-requirements.md`.
Cloud posture checks and Supabase audits are **beta** and not comprehensive; validate findings with manual review where required.

### 2b. AI Audit (Baseline + Agentic Expansion)
AI audit combines the deterministic `audit` pipeline with a bounded, tool-calling expansion phase for additional evidence collection (useful when Nmap finds multiple web ports). It produces one unified report.
```bash
supabash ai-audit 192.168.1.10 --yes
supabash audit 192.168.1.10 --agentic --yes   # alias
supabash ai-audit "http://192.168.1.10" --yes --llm-plan --max-actions 8

# Agentic audit with PCI profile
supabash ai-audit 192.168.1.10 --yes --compliance pci

# Agentic audit with SOC2 profile
supabash ai-audit 192.168.1.10 --yes --compliance soc2

# Agentic audit with ISO 27001 profile
supabash ai-audit 192.168.1.10 --yes --compliance iso

# Agentic audit with DORA profile
supabash ai-audit 192.168.1.10 --yes --compliance dora

# Agentic audit with NIS2 profile
supabash ai-audit 192.168.1.10 --yes --compliance nis2

# Agentic audit with GDPR profile
supabash ai-audit 192.168.1.10 --yes --compliance gdpr

# Agentic audit with BSI profile
supabash ai-audit 192.168.1.10 --yes --compliance bsi


```
Notes:
- AI audit uses provider tool-calling to plan additional evidence collection. If tool-calling is unsupported, Supabash logs a warning, skips the agentic phase, and still produces the baseline report.
- Agentic planning uses a `profile` field (`fast|standard|aggressive|compliance_*`) to guide assessment intensity and compliance posture.
- Baseline pipeline uses fast port discovery (`rustscan` and `masscan` fallback) before nmap service detection when applicable.
- Baseline web coverage runs one broad nuclei pass across deduplicated live targets, then deep scans on prioritized top targets.
- Agentic loop applies repeat-policy and low-novelty guards to avoid noisy loops and stop on diminishing returns.
- Domain expansion can use `subfinder` (when enabled), with in-scope filtering, optional DNS resolve validation, and bounded promotion to web probing.
- Compliance profiles tune tool settings and annotate findings with control references when evidence supports a requirement.
- Reports include compliance profile/focus in methodology, scope assumptions, a compliance coverage matrix, not-assessable areas, and deterministic recommended next actions.
- Each AI-audit run writes trace sidecars:
  - `<slug>-replay.json` + `<slug>-replay.md` (step-by-step reproducibility trace)
  - `<slug>-llm-trace.json` + `<slug>-llm-trace.md` (explicit planner/decision event stream)
- Live terminal status includes planner decisions (candidate selection, replan, selected action, critique).
- LLM trace captures explicit planner messages and decisions only; hidden model-internal reasoning is not exposed by API providers.
- AI audit writes JSON + Markdown by default; HTML/PDF exports are optional via `core.report_exports`.

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
/audit 192.168.1.10 --mode normal --remediate  # writes reports/report-YYYYmmdd-HHMMSS/report-YYYYmmdd-HHMMSS.{json,md}
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
  - `--output`, `-o` — output JSON path (default: `reports/<slug>/<slug>.json`; slug is `report-YYYYmmdd-HHMMSS`, or `ai-audit(-<profile>)-YYYYmmdd-HHMMSS` when `--agentic` is set)
  - `--markdown`, `-m` — output Markdown path (default: derived from `--output`)
  - `--status/--no-status` (default: `--status`) — print live progress
  - `--status-file` — write JSON status updates while running
  - `--container-image`, `-c` — optional container image to scan with Trivy
  - `--force` — bypass allowed-hosts check
  - `--allow-public` — allow public IP targets (authorized only)
  - `--yes` — skip consent prompt
  - `--mode` (default: `normal`) — `normal|stealth|aggressive`
  - `--compliance` — compliance profile (`pci|soc2|iso|dora|nis2|gdpr|bsi`)
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
  - `--medusa` — opt-in Medusa bruteforce (defaults module/port from nmap)
  - `--medusa-usernames` — usernames file or single username
  - `--medusa-passwords` — passwords file or single password
  - `--medusa-module` — explicit module/service (optional)
  - `--medusa-port` — explicit port (optional)
  - `--medusa-threads` (default: `4`) — medusa `-t` threads
  - `--medusa-timeout` (default: `10`) — timeout per connection (seconds)
  - `--medusa-options` — extra medusa CLI options
  - `--crackmapexec`, `--cme` — opt-in CrackMapExec/NetExec
  - `--cme-protocol` (default: `smb`) — protocol (`smb|ssh|ldap|winrm|mssql|rdp`)
  - `--cme-username` — username
  - `--cme-password` — password
  - `--cme-domain` — domain
  - `--cme-hashes` — NTLM hashes (LM:NT or NT)
  - `--cme-module` — module to run
  - `--cme-module-options` — module options
  - `--cme-enum` — enumeration flags (comma-separated)
  - `--cme-args` — extra CME args (allows anonymous runs)
  - `--theharvester` — opt-in OSINT (domain targets only)
  - `--theharvester-sources` — comma-separated data sources
  - `--theharvester-limit` — results per source (default: 500)
  - `--theharvester-start` — start index (default: 0)
  - `--theharvester-args` — extra theHarvester CLI args
  - `--netdiscover` — opt-in LAN discovery (private CIDR only; requires sudo)
  - `--netdiscover-range` — CIDR range (e.g. `192.168.1.0/24`)
  - `--netdiscover-interface` — network interface (e.g. `eth0`)
  - `--netdiscover-passive` — passive sniffing mode
  - `--netdiscover-fast/--netdiscover-no-fast` — fast mode toggle
  - `--netdiscover-args` — extra netdiscover CLI args
  - `--aircrack`, `--aircrack-ng` — opt-in Aircrack-ng suite (WiFi)
  - `--aircrack-interface` — wireless interface for airodump-ng (e.g. `wlan0mon`)
  - `--aircrack-channel` — WiFi channel to lock during capture
  - `--aircrack-args` — extra airodump-ng CLI args
  - `--aircrack-airmon` — auto start/stop monitor mode with airmon-ng
  - `--scoutsuite` — opt-in ScoutSuite (multi-cloud)
  - `--scoutsuite-provider` (default: `aws`) — `aws|azure|gcp`
  - `--scoutsuite-args` — extra ScoutSuite CLI arguments
  - `--prowler` — opt-in Prowler (AWS)
  - `--prowler-args` — extra Prowler CLI arguments
  - `--remediate` — LLM remediation (steps + code snippets)
  - `--no-llm` — disable LLM for this run
  - `--agentic` — agentic audit mode (baseline + bounded expansion)
  - `--llm-plan/--no-llm-plan` — tool-calling LLM planning for agentic expansion (only with `--agentic`)
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
- default output is `reports/ai-audit-<profile>-YYYYmmdd-HHMMSS/ai-audit-<profile>-YYYYmmdd-HHMMSS.json` when `--compliance` is set, otherwise `reports/ai-audit-YYYYmmdd-HHMMSS/ai-audit-YYYYmmdd-HHMMSS.json` (+ `.md`; html/pdf when enabled)
  - `--compliance` — compliance profile (`pci|soc2|iso|dora|nis2|gdpr|bsi`)
  - `--status/--no-status` (default: `--status`) — print live progress
  - `--status-file` — write JSON status updates while running
  - `--llm-plan/--no-llm-plan` — tool-calling LLM planning for agentic expansion
  - `--max-actions` (default: `10`) — cap agentic expansion length
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
- Control verbosity via `core.log_level` (`INFO`, `DEBUG`, etc.); logs are written to `./debug.log` by default (override with `SUPABASH_LOG_DIR`).
- Enable/disable tools globally via `tools.<tool>.enabled` (see `config.yaml.example`).
- Set per-tool timeouts via `tools.<tool>.timeout_seconds` (0 disables the timeout).
- Fast discovery tuning: `tools.nmap.fast_discovery`, `tools.nmap.fast_discovery_ports`, `tools.nmap.fast_discovery_max_ports`.
- Set a default Nuclei throttling rate via `tools.nuclei.rate_limit` (overridden by `--nuclei-rate`).
- Optionally scope Nuclei templates with `tools.nuclei.tags` or `tools.nuclei.severity` for faster audits.
- Domain expansion tuning (when enabled): `tools.subfinder.max_candidates`, `tools.subfinder.max_promoted_hosts`, `tools.subfinder.resolve_validation`.
- Offline/no-LLM mode: set `llm.enabled=false` in `config.yaml` or pass `--no-llm` on `audit`/`ai-audit`.
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
- Model compatibility fallback: if a provider/model rejects `temperature`, Supabash automatically retries LLM calls without `temperature` (useful for stricter model APIs).
- LLM payload + caching knobs (advanced):
  - `llm.max_input_chars` — hard cap (characters) on what gets sent to the LLM per request (higher = more context/cost).
  - `llm.max_input_tokens` — fallback token window size used only for showing chat “context %” when the model limit can’t be detected (common for local servers); `0` disables the fallback.
  - `llm.cache_enabled` — enable/disable caching of identical LLM calls.
  - `llm.cache_ttl_seconds` / `llm.cache_max_entries` — cache retention controls (time-to-live and max number of entries).
- Tune web tooling: `supabash audit ... --nuclei-rate 10 --gobuster-threads 20` (and optionally `--gobuster-wordlist /path/to/list`).
- Parallelize web tools: `supabash audit ... --parallel-web --max-workers 3` (URL targets can overlap recon with web tooling).
- Safety caps (aggressive mode): Supabash enforces global caps (rate limits / concurrency) in `--mode aggressive`; configure via `core.aggressive_caps` in `config.yaml`.
- Agentic profiles: AI audit planning uses `profile` (`fast|standard|aggressive|compliance_*`) to drive compliance-oriented tool settings and reporting.

---

## ✅ Implemented Wrappers (27 Tools)

### Core Audit Pipeline (runs by default)
Fast discovery (rustscan/masscan) → targeted Nmap service detection → httpx probing → broad Nuclei pass (deduped live targets) → prioritized deep web scans (WhatWeb/Gobuster/Katana) (+ conditional Dnsenum/sslscan/enum4linux-ng, and optional Sqlmap/Supabase Audit/Trivy/WPScan)

### Recon & Discovery (9 tools)
| Tool | Purpose | Trigger |
|------|---------|---------|
| **Nmap** | Port scanning & service detection | Default recon |
| **Masscan** | High-speed port scanning | `--scanner masscan` |
| **Rustscan** | Fast port scanner | `--scanner rustscan` |
| **httpx** | HTTP probing / alive endpoints | Auto (web ports) |
| **subfinder** | Subdomain discovery | `tools.subfinder.enabled=true` |
| **Dnsenum** | DNS enumeration | Auto (domain targets) |
| **Sslscan** | SSL/TLS analysis | Auto (TLS candidate ports from discovery, including non-standard ports) |
| **Enum4linux-ng** | SMB/Samba enumeration | Auto (139/445 ports) |
| **Netdiscover** | ARP network discovery | `--netdiscover` (private LAN) |

### Web & Vulnerability (9 tools)
| Tool | Purpose | Trigger |
|------|---------|---------|
| **WhatWeb** | Technology detection | Auto (web ports) |
| **Nuclei** | Template-based vuln scanning | Default pipeline |
| **Gobuster** | Directory brute-forcing | Default pipeline |
| **ffuf** | Content discovery (fallback) | `tools.ffuf.enabled=true` |
| **Nikto** | Web server scanning | `--nikto` flag |
| **Sqlmap** | SQL injection detection | Auto (parameterized URLs) |
| **katana** | Web crawling/spidering | `tools.katana.enabled=true` |
| **Searchsploit** | Offline exploit references | `tools.searchsploit.enabled=true` |
| **WPScan** | WordPress security scanner | Auto (WordPress detected) |

### Credentials & Post-Exploitation (4 tools)
| Tool | Purpose | Trigger |
|------|---------|---------|
| **Hydra** | Login brute-forcing | `--hydra` + wordlists |
| **Medusa** | Parallel login brute-forcing | `--medusa` |
| **CrackMapExec/NetExec** | AD/Windows post-exploitation | `--crackmapexec` |
| **TheHarvester** | OSINT (emails, subdomains) | `--theharvester` (domain targets) |

### Wireless (1 tool)
| Tool | Purpose | Trigger |
|------|---------|---------|
| **Aircrack-ng** | WiFi discovery (airodump-ng capture) | `--aircrack` |

### Container & Cloud (4 tools)
| Tool | Purpose | Trigger |
|------|---------|---------|
| **ScoutSuite** | Multi-cloud posture assessment (beta coverage) | `--scoutsuite` |
| **Prowler** | AWS security best-practice checks (beta coverage) | `--prowler` |
| **Trivy** | Container image CVE scanning | `--container-image` |
| **Supabase Audit** | RLS, URL/key/RPC exposure checks (beta heuristics) | Auto (web targets) |

### AI & Orchestration
- **AI audit (agentic):** `supabash ai-audit ...` (or `supabash audit --agentic ...`) runs the baseline audit + a bounded expansion phase and writes one unified report.
- **LLM integration:** litellm-based client with config-driven provider/model selection (OpenAI, Anthropic, Gemini, Mistral, Ollama, LM Studio)
- **Chat mode:** slash commands `/scan`, `/audit`, `/status`, `/stop`, `/details`, `/report`, `/test`, `/summary`, `/fix`, `/plan`, `/clear-state`
- **Planner robustness:** one-time automatic replan with exclusions when candidates are already baseline-covered.
- **Repeat/novelty guards:** tool-target reuse caps and low-signal penalties reduce redundant agentic retries.

### Reporting
- **Formats:** Timestamped run folders under `reports/` containing JSON + Markdown reports (and optional HTML/PDF) with command traces for auditability
- **Schema:** JSON reports include `schema_version` + `schema_validation` for validation and forward compatibility
- **Styling:** Markdown reports include TOC + summary tables for readability
- **Compliance context:** Reports capture compliance profile/focus and annotate relevant findings with control references
- **Traceability:** AI-audit includes replay and LLM reasoning trace sidecars (`-replay.{json,md}`, `-llm-trace.{json,md}`) plus decision-trace highlights in the main report
- **Export:** Optional HTML/PDF export via WeasyPrint

---

## 📊 Example Report Output
Example: [reports](example_reports/)  

When Supabash detects an issue, it provides evidence-based findings and remediation guidance:

```json
{
  "severity": "HIGH",
  "title": "SQL injection detected",
  "tool": "sqlmap",
  "evidence": "Parameter `user` appears vulnerable to boolean-based blind SQLi on /login.php?user=.",
  "recommendation": "Use parameterized queries (PDO prepared statements) and validate input.",
  "remediation": {
    "steps": [
      "Replace string concatenation with parameterized queries.",
      "Add server-side input validation for `user`."
    ],
    "code_sample": "$stmt = $pdo->prepare('SELECT * FROM users WHERE user = :user');"
  }
}
```

---

## ⚖️ Assurance Disclaimer (SOC/ISO/PCI)

Supabash Audit is **not** an independent attestation. Supabash is **not** a CPA firm or certification body and does **not** perform independent attestation engagements. Outputs are **not** SOC 1/2/3 reports and are **not** ISO certifications. Supabash is intended for **readiness, internal review, and evidence collection** to support third‑party assessments.

## ⚠️ Legal Disclaimer

**Supabash is for educational purposes and authorized security assessment/testing only.**

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
