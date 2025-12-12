
# SUPABASH

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
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-WIP-orange)

> **⚠️ Development Status:** This project is currently in **Active Development (Phase 3)**. The CLI, tool wrappers, chat control plane, audit reporting (JSON/Markdown), and LLM-based summary/remediation are implemented; the full autonomous ReAct loop and deeper safety/reporting polish are still in progress.  
> Progress: `[███████████████-----]` **76%**

**Supabash** is an autonomous AI Security Agent designed for developers, DevOps engineers, and pentesters. Unlike traditional wrapper scripts, Supabash acts as a **reasoning engine**: it intelligently orchestrates industry-standard security tools, analyzes their output in real-time, identifies security holes, and writes detailed audit reports with actionable remediation steps.

**Don't just find the vulnerability. Bash it, understand it, and fix it.**

---

## 🚀 Key Features

*   **🤖 Autonomous Reasoning:** The agent decides which tools to run based on the initial scan results (ReAct Pattern).
*   **🛡️ Full-Stack Auditing:** Scans infrastructure, Docker containers, web applications, and wireless networks.
*   **📝 Smart Reporting:** Generates human-readable audits containing detection details, severity levels, and **code-level fix suggestions**.
*   **⚡ High-Performance:** Orchestrates fast scanners (Rust/Go) alongside deep-dive frameworks (Python/Ruby).
*   **🔌 Plugin Architecture:** Easily extensible tool definitions.

---

## 🛠️ The Arsenal

Supabash comes pre-configured to orchestrate the following tools. The agent manages the installation and execution of these dependencies.

### 🔍 Recon & Discovery
*   **Nmap** (Network mapping & service detection)
*   **Masscan** (High-speed port scanning)
*   **Rustscan** (Modern, fast port scanner)
*   **Netdiscover** (ARP reconnaissance)
*   **Dnsenum** (DNS enumeration)
*   **Sslscan** (SSL/TLS analysis)
*   **Enum4linux** (SMB/Samba enumeration)

### 🌐 Web & Exploit
*   **Metasploit Framework** (Exploitation & validation)
*   **Sqlmap** (Automated SQL injection)
*   **Gobuster** (Directory & file brute-forcing)
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

### Manual Installation
1.  Install system dependencies (see `requirements_system.txt`).
2.  Install Python libraries:
    ```bash
    pip3 install -r requirements.txt
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

### 2. Full Application Audit
Run a comprehensive audit including recon, web scanning, and optional container scanning, then generate a report.
```bash
# Ensure the target is listed in core.allowed_hosts in config.yaml (recommended),
# or pass --force to bypass the scope check.
supabash audit 192.168.1.10 --output report.json --yes
# include container image scan
supabash audit 192.168.1.10 --container-image my-app:latest --output report.json --yes
# write markdown report too
supabash audit 192.168.1.10 --markdown report.md --yes
# run sqlmap only when providing a parameterized URL
supabash audit "http://192.168.1.10/?id=1" --output report.json --yes
```

### 3. Container Image Scan
Scan a local Docker image for CVEs and configuration issues (via Trivy).
```bash
supabash audit 127.0.0.1 --container-image my-app:latest --output report.json --yes
```

### 4. Interactive Mode
Talk to the agent directly to plan a custom engagement (slash commands supported).
```bash
supabash chat
# inside chat:
/scan 192.168.1.10 --profile fast --scanner nmap  # add --allow-public only if authorized
/details      # show last scan
/report out.json
/test         # run unit tests
/summary      # LLM summary (requires configured provider/key)
/fix "SQL Injection" "param id injectable"  # LLM remediation
/plan         # heuristic next steps
```

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
- Restrict scope via `core.allowed_hosts` (IPs/hosts/CIDRs/wildcards like `*.corp.local`); add your own infra there. Use `--force` on `scan`/`audit` to bypass.
- Public IP guardrail: IP-literal public targets are blocked by default; enable with `core.allow_public_ips=true`, `supabash config --allow-public-ips`, or per-run `--allow-public` (only if authorized).
- Edit allowed hosts via CLI: `supabash config --allow-host 10.0.0.0/24`, `supabash config --remove-host 10.0.0.0/24`, `supabash config --list-allowed-hosts`.
- Manage providers, API keys, and models with `supabash config`.
- Manage scan safety: consent prompts are remembered in `core.consent_accepted` after the first interactive acceptance (use `supabash config --reset-consent` to re-prompt); `--yes` skips prompting for a single run.
- Tune web tooling: `supabash audit ... --nuclei-rate 10 --gobuster-threads 20` (and optionally `--gobuster-wordlist /path/to/list`).

---

## ✅ Implemented Wrappers (Beta)
- Nmap (used by `supabash scan`)
- Masscan (library wrapper for fast port discovery)
- Rustscan (fast scanner using nmap greppable output)
- Nikto (web scanner)
- Nuclei (template-based vuln scanner)
- Gobuster (directory brute-forcing)
- WhatWeb (tech stack detection)
- sqlmap (SQL injection detection)
- Hydra (credential brute-forcing)
- Trivy (container image vulnerability scanning)
- Supabase RLS checker (public access detection)
- LLM client wrapper (litellm-based) with config-driven provider/model selection
- Chat session with slash commands (/scan, /details, /report, /test, /summary, /fix, /plan)
- Markdown report generator (`--markdown`) with findings aggregation

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

## 🤝 Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request
