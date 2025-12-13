# System Requirements (Manual Install)

Supabash is designed for **Linux** (Kali/Ubuntu/Debian/WSL2). If you don’t use `install.sh`, you must install the required system binaries yourself.

## Debian/Ubuntu/Kali (APT)

Core packages used by the current wrappers and audit flow:
```bash
sudo apt-get update -y
sudo apt-get install -y \\
  python3 python3-pip python3-venv \\
  git curl wget jq unzip \\
  nmap masscan nuclei nikto sqlmap hydra gobuster whatweb \\
  sslscan dnsenum enum4linux \\
  trivy
```

Notes:
- On Ubuntu, you may need to enable `universe` for some packages: `sudo add-apt-repository universe && sudo apt-get update -y`.
- Ubuntu 24.04 may not ship `enum4linux` as an APT package; try `enum4linux-ng` instead.
- `nuclei` and `trivy` can also be installed via their upstream installers; `install.sh` includes one working path.
- Some tools are listed in README as a planned toolset but not all wrappers are implemented yet.

## Python dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
