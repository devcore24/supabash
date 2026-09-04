# System Requirements (Manual Install)

Supabash is designed for **Linux** (Kali/Ubuntu/Debian/WSL2). If you don’t use `install.sh`, you must install the required system binaries yourself.

## Debian/Ubuntu/Kali (APT)

Core packages used by the current wrappers and audit flow:
```bash
sudo apt-get update -y
sudo apt-get install -y \\
  python3 python3-pip python3-venv \\
  git curl wget jq unzip \\
  nmap masscan nikto sqlmap hydra gobuster ffuf whatweb \\
  postgresql-client \\
  sslscan dnsenum
```

Notes:
- On Ubuntu, you may need to enable `universe` for some packages: `sudo add-apt-repository universe && sudo apt-get update -y`.
- `rustscan`, `httpx`, `nuclei`, `trivy`, `enum4linux`, `ffuf`, and `searchsploit` are not consistently available as APT packages across distros/versions; `install.sh` includes automated install paths for several of these, and will skip (with warnings) anything it can’t find.
- Ubuntu 24.04 does not ship `enum4linux` as an APT package in many setups; prefer `enum4linux-ng` (installed by `install.sh`).
- Some tools are listed in README as a planned toolset but not all wrappers are implemented yet.

### Optional tools (manual alternatives)

#### httpx (HTTP probing / alive web targets)
Install from GitHub release (Linux example):
```bash
(
set -euo pipefail
tag="v1.10.0"
ver="${tag#v}"
asset="httpx_${ver}_linux_amd64.zip"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL -o "$tmpdir/$asset" "https://github.com/projectdiscovery/httpx/releases/download/${tag}/${asset}"
curl -fsSL -o "$tmpdir/checksums.txt" "https://github.com/projectdiscovery/httpx/releases/download/${tag}/httpx_${ver}_checksums.txt"
(cd "$tmpdir" && grep -E "[[:space:]]${asset}$" checksums.txt | sha256sum -c -)
unzip -q "$tmpdir/$asset" -d "$tmpdir/unpacked"
sudo install -m 0755 "$tmpdir/unpacked/httpx" /usr/local/bin/httpx
rm -rf "$tmpdir"
trap - EXIT
)
```

#### subfinder (subdomain discovery)
Install from GitHub release (Linux example):
```bash
(
set -euo pipefail
tag="v2.14.0"
ver="${tag#v}"
asset="subfinder_${ver}_linux_amd64.zip"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL -o "$tmpdir/$asset" "https://github.com/projectdiscovery/subfinder/releases/download/${tag}/${asset}"
curl -fsSL -o "$tmpdir/checksums.txt" "https://github.com/projectdiscovery/subfinder/releases/download/${tag}/subfinder_${ver}_checksums.txt"
(cd "$tmpdir" && grep -E "[[:space:]]${asset}$" checksums.txt | sha256sum -c -)
unzip -q "$tmpdir/$asset" -d "$tmpdir/unpacked"
sudo install -m 0755 "$tmpdir/unpacked/subfinder" /usr/local/bin/subfinder
rm -rf "$tmpdir"
trap - EXIT
)
```

#### katana (crawler/spider)
Install from GitHub release (Linux example):
```bash
(
set -euo pipefail
tag="v1.6.1"
ver="${tag#v}"
asset="katana_${ver}_linux_amd64.zip"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL -o "$tmpdir/$asset" "https://github.com/projectdiscovery/katana/releases/download/${tag}/${asset}"
curl -fsSL -o "$tmpdir/checksums.txt" "https://github.com/projectdiscovery/katana/releases/download/${tag}/katana-${ver}-checksums.txt"
(cd "$tmpdir" && grep -E "[[:space:]]${asset}$" checksums.txt | sha256sum -c -)
unzip -q "$tmpdir/$asset" -d "$tmpdir/unpacked"
sudo install -m 0755 "$tmpdir/unpacked/katana" /usr/local/bin/katana
rm -rf "$tmpdir"
trap - EXIT
)
```

#### enum4linux-ng (SMB enumeration)
```bash
sudo apt-get install -y smbclient samba-common-bin python3-impacket python3-ldap3 python3-yaml
sudo curl -fsSL https://raw.githubusercontent.com/cddmp/enum4linux-ng/v1.3.10/enum4linux-ng.py -o /usr/local/bin/enum4linux-ng
sudo chmod +x /usr/local/bin/enum4linux-ng
```

#### searchsploit (Exploit-DB offline reference search)
On Kali Linux, `searchsploit` is commonly available via:
```bash
sudo apt-get install -y exploitdb
```

#### browser-use (browser-driven agentic validation)
```bash
pipx install uv
uv python install 3.12
pipx install --python "$(uv python find 3.12)" "browser-use==0.13.7"
pipx ensurepath
browser-use install
```

Supabash uses the isolated installation's Python interpreter and browser-use
library for guarded scans. That path enforces the engagement's exact origins
with `Browser.allowed_domains`. Native CLI runs, named sessions, and custom
commands are not accepted for guarded execution because they cannot provide the
same preventive boundary; the legacy deterministic CLI fallback is disabled.

If `browser-use install` fails with a `uvx` permission/runtime error:
```bash
pipx install --force uv
uv python install 3.12
browser-use install
```

Credential options for Supabash:
- export `BROWSER_USE_API_KEY` in the shell that runs `supabash`
- or set `tools.browser_use.api_key` in `config.yaml`
- or set `tools.browser_use.api_key_env` and let Supabash map that env var to `BROWSER_USE_API_KEY`

Prefer environment variables over storing a live Browser-Use key in a repo-tracked `config.yaml`.

## Runtime notes

- `katana` is enabled by default in the current config template and participates in deep web baseline coverage unless disabled.
- `tools.nuclei.rate_limit` is the main runtime throttle for both baseline and targeted Nuclei scans.
- `tools.nuclei.normal_mode_broad_rate_limit` is optional and affects only the broad multi-target baseline pass in `normal` mode.
- Set `tools.nuclei.normal_mode_broad_rate_limit: 0` to fully honor `tools.nuclei.rate_limit`.
- SQLMap target harvesting is conservative: Supabash strips evidence suffixes from harvested URLs and blocks object-store listing-style query params such as `list-type`, `prefix`, and `delimiter` from becoming automatic SQLMap targets.
- `postgresql-client` provides `psql` and `pg_isready`, which Supabash uses for safe PostgreSQL readiness/auth-posture checks. If `psql` is missing, Supabash falls back to `pg_isready` and records a degraded posture signal instead of claiming auth was verified.

## Python dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
