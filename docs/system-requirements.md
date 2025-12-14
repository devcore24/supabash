# System Requirements (Manual Install)

Supabash is designed for **Linux** (Kali/Ubuntu/Debian/WSL2). If you don’t use `install.sh`, you must install the required system binaries yourself.

## Debian/Ubuntu/Kali (APT)

Core packages used by the current wrappers and audit flow:
```bash
sudo apt-get update -y
sudo apt-get install -y \\
  python3 python3-pip python3-venv \\
  git curl wget jq unzip \\
  nmap masscan nikto sqlmap hydra gobuster whatweb \\
  sslscan dnsenum
```

Notes:
- On Ubuntu, you may need to enable `universe` for some packages: `sudo add-apt-repository universe && sudo apt-get update -y`.
- `rustscan`, `nuclei`, `trivy`, and `enum4linux` are not consistently available as APT packages across distros/versions; `install.sh` includes a working automated path for these.
- Ubuntu 24.04 does not ship `enum4linux` as an APT package in many setups; prefer `enum4linux-ng` (installed by `install.sh`).
- Some tools are listed in README as a planned toolset but not all wrappers are implemented yet.

### Optional tools (manual alternatives)

#### enum4linux-ng (SMB enumeration)
```bash
sudo apt-get install -y smbclient samba-common-bin python3-impacket python3-ldap3 python3-yaml
sudo curl -fsSL https://raw.githubusercontent.com/cddmp/enum4linux-ng/v1.3.7/enum4linux-ng.py -o /usr/local/bin/enum4linux-ng
sudo chmod +x /usr/local/bin/enum4linux-ng
```

## Python dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
