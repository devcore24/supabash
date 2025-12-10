
# SUPABASH

```text
   _____                  _               _     
  / ____|                | |             | |    
 | (___  _   _ _ __   __ | |__   __ _ ___| |__  
  \___ \| | | | '_ \ / _` | '_ \ / _` / __| '_ \ 
  ____) | |_| | |_) | (_| | |_) | (_| \__ \ | | |
 |_____/ \__,_| .__/ \__,_|_.__/ \__,_|___/_| |_|
              | |                                
              |_|                                
```

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Beta-orange)

**SupaBash** is an autonomous AI Security Agent designed for developers, DevOps engineers, and pentesters. Unlike traditional wrapper scripts, SupaBash acts as a **reasoning engine**: it intelligently orchestrates industry-standard security tools, analyzes their output in real-time, identifies security holes, and writes detailed audit reports with actionable remediation steps.

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

SupaBash comes pre-configured to orchestrate the following tools. The agent manages the installation and execution of these dependencies.

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

SupaBash requires **Linux** (Kali, Ubuntu, Debian) or **WSL2**.

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
Launch a smart scan against a target. The agent will start with Nmap and escalate to Web scanners if ports 80/443 are open.
```bash
supabash scan 192.168.1.10
```

### 2. Full Application Audit
Run a comprehensive audit including container security and web vulnerabilities, then generate a fix report.
```bash
supabash audit --target 192.168.1.10 --output report.json
```

### 3. Container Mode
Scan a local Docker image for CVEs and configuration issues.
```bash
supabash docker my-app:latest
```

### 4. Interactive Mode
Talk to the agent directly to plan a custom engagement.
```bash
supabash chat
> "Scan the target for SQL injection and tell me how to patch the code."
```

---

## 📊 Example Audit Output

When SupaBash detects an issue, it provides context and solutions:

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

**SupaBash is for educational purposes and authorized security auditing only.**

Usage of SupaBash for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 🤝 Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request
