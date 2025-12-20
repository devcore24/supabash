#!/bin/bash

# Supabash Installer
# Installs dependencies, sets up the environment, and configures the CLI.

set -e

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
BLUE="\033[34m"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

RUSTSCAN_VERSION="${RUSTSCAN_VERSION:-2.4.1}"
RUSTSCAN_REPO="${RUSTSCAN_REPO:-bee-san/RustScan}"
HTTPX_VERSION="${HTTPX_VERSION:-latest}"
HTTPX_REPO="${HTTPX_REPO:-projectdiscovery/httpx}"
SUBFINDER_VERSION="${SUBFINDER_VERSION:-latest}"
SUBFINDER_REPO="${SUBFINDER_REPO:-projectdiscovery/subfinder}"
KATANA_VERSION="${KATANA_VERSION:-latest}"
KATANA_REPO="${KATANA_REPO:-projectdiscovery/katana}"
ENUM4LINUX_NG_VERSION="${ENUM4LINUX_NG_VERSION:-v1.3.7}"
ENUM4LINUX_NG_REPO="${ENUM4LINUX_NG_REPO:-cddmp/enum4linux-ng}"
# Optional: update nuclei templates for the invoking (non-root) user after install
SUPABASH_UPDATE_NUCLEI_TEMPLATES="${SUPABASH_UPDATE_NUCLEI_TEMPLATES:-1}"
# Optional: install PDF/HTML report export dependencies (WeasyPrint)
SUPABASH_PDF_EXPORT="${SUPABASH_PDF_EXPORT:-0}"

# Optional manual installers (fallbacks for GitHub asset detection)
install_via_go() {
    local name="$1"
    local module="$2"
    local version="$3"

    if command -v "$name" >/dev/null 2>&1; then
        return 0
    fi
    if ! command -v go >/dev/null 2>&1; then
        warn "Go toolchain not found; cannot install ${name} via go install."
        return 1
    fi

    local mod_ref="$module@${version:-latest}"
    info "Installing ${name} via go install (${mod_ref})..."

    local tmpdir
    tmpdir="$(mktemp -d)"
    local gobin
    gobin="${tmpdir}/bin"
    mkdir -p "$gobin"

    if ! GO111MODULE=on GOBIN="$gobin" go install -v "$mod_ref" >/tmp/${name}-go-install.log 2>&1; then
        warn "go install failed for ${name}. See /tmp/${name}-go-install.log"
        rm -rf "$tmpdir"
        return 1
    fi

    if [ ! -x "${gobin}/${name}" ]; then
        warn "go install finished but ${name} binary not found at ${gobin}/${name}."
        rm -rf "$tmpdir"
        return 1
    fi

    $SUDO install -m 0755 "${gobin}/${name}" "/usr/local/bin/${name}"
    rm -rf "$tmpdir"
    if command -v "$name" >/dev/null 2>&1; then
        success "${name} installed via go install."
        return 0
    fi
    warn "${name} installed via go install, but not found on PATH."
    return 1
}

migrate_trivy_keyring() {
    local list_file="/etc/apt/sources.list.d/trivy.list"
    local new_key="/etc/apt/keyrings/trivy.gpg"
    if [ -f "$list_file" ] && grep -q "trusted.gpg" "$list_file"; then
        info "Migrating Trivy apt key to ${new_key} (to silence legacy keyring warning)..."
        $SUDO mkdir -p /etc/apt/keyrings
        if $SUDO gpg --no-default-keyring --keyring /etc/apt/trusted.gpg --export aquasecurity | $SUDO tee "$new_key" >/dev/null; then
            $SUDO chmod a+r "$new_key"
            $SUDO sed -i "s|/etc/apt/trusted.gpg|${new_key}|g" "$list_file"
            success "Trivy key migrated to ${new_key}."
        else
            warn "Could not export Trivy key from trusted.gpg; leaving existing configuration."
        fi
    fi
}

info() {
    echo -e "${BLUE}[INFO]${RESET} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${RESET} $1"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $1"
    exit 1
}

warn() {
    echo -e "\033[33m[WARN]${RESET} $1"
}

# 1. OS Detection
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Cannot detect OS. This script requires Linux."
    fi
    info "Detected OS: $OS $VER"
}

# Enable Ubuntu "universe" repo for common security tools
enable_ubuntu_universe() {
    if [[ "${OS,,}" == *"ubuntu"* ]]; then
        if ! command -v add-apt-repository &> /dev/null; then
            info "Installing software-properties-common (for add-apt-repository)..."
            $SUDO apt-get update -y
            $SUDO apt-get install -y software-properties-common
        fi
        info "Ensuring Ubuntu 'universe' repository is enabled..."
        $SUDO add-apt-repository -y universe >/dev/null 2>&1 || true
        $SUDO apt-get update -y
    fi
}

install_exploitdb() {
    # Prefer distro package if available
    if command -v searchsploit >/dev/null 2>&1; then
        info "exploitdb/searchsploit already installed."
        return 0
    fi

    if apt_pkg_available "exploitdb"; then
        info "Installing exploitdb via APT..."
        $SUDO apt-get install -y exploitdb || warn "Failed to install exploitdb from APT."
        if command -v searchsploit >/dev/null 2>&1; then
            success "exploitdb installed via APT."
            return 0
        fi
    fi

    # Fallback: git clone
    info "Falling back to git install of exploitdb (searchsploit)..."
    local target_dir="/opt/exploitdb"
    local bin_path="/usr/local/bin/searchsploit"
    if [ ! -d "$target_dir" ]; then
        $SUDO git clone https://gitlab.com/exploit-database/exploitdb.git "$target_dir" || {
            warn "Git clone of exploitdb failed; please install manually."
            return 1
        }
    else
        info "Updating existing exploitdb clone..."
        (cd "$target_dir" && $SUDO git pull --ff-only) || warn "Failed to update exploitdb; continuing with existing copy."
    fi

    $SUDO ln -sf "$target_dir/searchsploit" "$bin_path"
    if command -v searchsploit >/dev/null 2>&1; then
        success "searchsploit installed at ${bin_path}."
    else
        warn "searchsploit symlink created but not detected on PATH; check ${bin_path}."
    fi

    # Optional extra packages
    if apt_pkg_available "exploitdb-bin-sploits"; then
        $SUDO apt-get install -y exploitdb-bin-sploits exploitdb-papers || true
    fi
}

apt_pkg_available() {
    apt-cache show "$1" >/dev/null 2>&1
}

fetch_github_release_json() {
    local repo="$1"
    local version="$2"
    local url=""

    if [ -z "$version" ] || [ "$version" = "latest" ]; then
        url="https://api.github.com/repos/${repo}/releases/latest"
        curl -fsSL "$url"
        return 0
    fi

    # Try exact tag, then v-prefixed tag, then latest
    url="https://api.github.com/repos/${repo}/releases/tags/${version}"
    if curl -fsSL "$url" 2>/dev/null; then
        return 0
    fi
    url="https://api.github.com/repos/${repo}/releases/tags/v${version}"
    if curl -fsSL "$url" 2>/dev/null; then
        return 0
    fi
    url="https://api.github.com/repos/${repo}/releases/latest"
    curl -fsSL "$url"
}

pick_release_asset_url() {
    local release_json="$1"
    local pattern="$2"
    echo "$release_json" | jq -r --arg pat "$pattern" '.assets[] | select(.name|test($pat)) | .browser_download_url' | head -n 1
}

download_url_to_tmp() {
    local url="$1"
    local tmpdir="$2"
    local name="$3"
    if command -v curl &> /dev/null; then
        curl -fsSL "$url" -o "${tmpdir}/${name}" >/dev/null 2>&1 || return 1
    else
        wget -qO "${tmpdir}/${name}" "$url" >/dev/null 2>&1 || return 1
    fi
    [ -s "${tmpdir}/${name}" ]
}

install_github_zip_binary() {
    local name="$1"
    local repo="$2"
    local version="$3"
    local pat_amd64="$4"
    local pat_arm64="$5"

    if command -v "$name" &> /dev/null; then
        info "${name} is already installed."
        return 0
    fi

    info "Installing ${name} from GitHub release..."
    local arch asset_url asset_name tmpdir bin_path release_json
    arch="$(uname -m)"
    asset_url=""

    if command -v jq &> /dev/null; then
        release_json="$(fetch_github_release_json "$repo" "$version" || true)"
        if [ -n "$release_json" ]; then
            if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
                asset_url="$(pick_release_asset_url "$release_json" "$pat_amd64")"
            elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
                asset_url="$(pick_release_asset_url "$release_json" "$pat_arm64")"
            fi
        fi
    fi

    if [ -z "$asset_url" ]; then
        warn "Could not find a suitable ${name} release asset for arch=${arch} in repo=${repo} (version=${version})."
        warn "Try installing manually: https://github.com/${repo}/releases"
        return 1
    fi

    asset_name="$(basename "$asset_url")"
    tmpdir="$(mktemp -d)"
    download_url_to_tmp "$asset_url" "$tmpdir" "$asset_name" || true
    if [ ! -s "${tmpdir}/${asset_name}" ]; then
        warn "Failed to download ${name} package (${asset_name}). You may need to install it manually."
        rm -rf "$tmpdir"
        return 1
    fi

    unzip -q "${tmpdir}/${asset_name}" -d "${tmpdir}/${name}" || true
    bin_path="$(find "${tmpdir}/${name}" -maxdepth 4 -type f -name "$name" | head -n 1)"
    if [ -z "$bin_path" ]; then
        warn "${name} archive did not contain a '${name}' binary (skipping)."
        rm -rf "$tmpdir"
        return 1
    fi

    $SUDO install -m 0755 "$bin_path" "/usr/local/bin/${name}"
    rm -rf "$tmpdir"
    if command -v "$name" &> /dev/null; then
        success "${name} installed."
        return 0
    fi
    warn "${name} install attempted, but ${name} is still not on PATH."
    return 1
}

# 2. System Dependencies (APT)
install_apt_deps() {
    info "Updating package lists..."
    $SUDO apt-get update -y
    enable_ubuntu_universe

    DEPENDENCIES=(
        python3
        python3-pip
        python3-venv
        git
        curl
        wget
        unzip
        jq
        nmap
        masscan
        rustscan
        nikto
        sqlmap
        hydra
        medusa
        gobuster
        ffuf
        whatweb
        sslscan
        dnsenum
        netdiscover
        theharvester
        wpscan
        exploitdb # may be unavailable on some distros; handled below
        # Add other standard tools here
    )

    INSTALL=()
    MISSING=()
    for pkg in "${DEPENDENCIES[@]}"; do
        if apt_pkg_available "$pkg"; then
            INSTALL+=("$pkg")
            continue
        fi
        MISSING+=("$pkg")
    done

    info "Installing system packages: ${INSTALL[*]}"
    $SUDO apt-get install -y "${INSTALL[@]}"
    if [ "${#MISSING[@]}" -gt 0 ]; then
        warn "Some packages were not found in APT and were skipped: ${MISSING[*]}"
        warn "See docs/system-requirements.md for manual alternatives."
    fi
}

# 3. External Tools (Nuclei, Trivy)
install_external_tools() {
    install_exploitdb

    # Install Nuclei (ProjectDiscovery)
    if ! command -v nuclei &> /dev/null; then
        info "Installing Nuclei..."
        arch="$(uname -m)"
        if [[ "$arch" != "x86_64" && "$arch" != "amd64" ]]; then
            warn "Nuclei auto-install currently supports x86_64/amd64 only (arch=$arch). Install manually: https://github.com/projectdiscovery/nuclei/releases"
        else
            tmpdir="$(mktemp -d)"
            nuclei_zip="nuclei_2.9.8_linux_amd64.zip"
            nuclei_url="https://github.com/projectdiscovery/nuclei/releases/download/v2.9.8/${nuclei_zip}"
            if download_url_to_tmp "$nuclei_url" "$tmpdir" "$nuclei_zip"; then
                unzip -q "${tmpdir}/${nuclei_zip}" -d "$tmpdir"
                if [ -f "${tmpdir}/nuclei" ]; then
                    $SUDO install -m 0755 "${tmpdir}/nuclei" /usr/local/bin/nuclei
                    success "Nuclei installed."
                else
                    warn "Nuclei archive did not contain expected binary (skipping)."
                fi
            else
                warn "Failed to download Nuclei from ${nuclei_url} (skipping)."
            fi
            rm -rf "$tmpdir"
        fi

        if command -v nuclei &> /dev/null; then
            if [ "$SUPABASH_UPDATE_NUCLEI_TEMPLATES" = "1" ]; then
                info "Updating Nuclei templates for the invoking user (best-effort)..."
                if [ -n "${SUDO_USER:-}" ] && command -v sudo &> /dev/null; then
                    sudo -u "$SUDO_USER" -H nuclei -update-templates >/dev/null 2>&1 || warn "Nuclei template update failed; run: nuclei -update-templates"
                else
                    nuclei -update-templates >/dev/null 2>&1 || warn "Nuclei template update failed; run: nuclei -update-templates"
                fi
            else
                info "Skipping Nuclei template update (set SUPABASH_UPDATE_NUCLEI_TEMPLATES=1 to enable)."
            fi
        fi
    else
        info "Nuclei is already installed."
    fi

    # Install httpx (ProjectDiscovery HTTP probing)
    if ! command -v httpx &> /dev/null; then
        info "Installing httpx from GitHub release..."
        arch="$(uname -m)"
        asset_url=""

        if command -v jq &> /dev/null; then
            release_json="$(fetch_github_release_json "$HTTPX_REPO" "$HTTPX_VERSION" || true)"
            if [ -n "$release_json" ]; then
                if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
                    asset_url="$(pick_release_asset_url "$release_json" '^httpx_.*_linux_amd64\\.zip$')"
                elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
                    asset_url="$(pick_release_asset_url "$release_json" '^httpx_.*_linux_arm64\\.zip$')"
                fi
            fi
        fi

        if [ -z "$asset_url" ]; then
            warn "Could not find a suitable httpx release asset for arch=$arch in repo=$HTTPX_REPO (version=$HTTPX_VERSION)."
            warn "Try installing manually: https://github.com/${HTTPX_REPO}/releases"
        else
            asset_name="$(basename "$asset_url")"
            tmpdir="$(mktemp -d)"
            download_url_to_tmp "$asset_url" "$tmpdir" "$asset_name" || true
            if [ ! -s "${tmpdir}/${asset_name}" ]; then
                warn "Failed to download httpx package (${asset_name}). You may need to install it manually."
                rm -rf "$tmpdir"
            else
                unzip -q "${tmpdir}/${asset_name}" -d "${tmpdir}/httpx" || true
                bin_path="$(find "${tmpdir}/httpx" -maxdepth 3 -type f -name httpx | head -n 1)"
                if [ -z "$bin_path" ]; then
                    warn "httpx archive did not contain a 'httpx' binary (skipping)."
                else
                    $SUDO install -m 0755 "$bin_path" /usr/local/bin/httpx
                fi
                rm -rf "$tmpdir"
                if command -v httpx &> /dev/null; then
                    success "httpx installed."
                else
                    warn "httpx install attempted, but httpx is still not on PATH."
                fi
            fi
        fi
    else
        info "httpx is already installed."
    fi

    # Install subfinder (ProjectDiscovery subdomain discovery)
    if ! install_github_zip_binary "subfinder" "$SUBFINDER_REPO" "$SUBFINDER_VERSION" '^subfinder_.*_linux_amd64\\.zip$' '^subfinder_.*_linux_arm64\\.zip$'; then
        warn "Falling back to go install for subfinder (if Go is available)."
        install_via_go "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "$SUBFINDER_VERSION" || true
    fi

    # Install katana (ProjectDiscovery crawler)
    if ! install_github_zip_binary "katana" "$KATANA_REPO" "$KATANA_VERSION" '^katana_.*_linux_amd64\\.zip$' '^katana_.*_linux_arm64\\.zip$'; then
        warn "Falling back to go install for katana (if Go is available)."
        install_via_go "katana" "github.com/projectdiscovery/katana/cmd/katana" "$KATANA_VERSION" || true
    fi

    # Install Trivy (Container Scanner)
    if ! command -v trivy &> /dev/null; then
        info "Installing Trivy..."
        $SUDO apt-get install -y wget apt-transport-https gnupg lsb-release
        $SUDO install -m 0755 -d /etc/apt/keyrings
        if command -v curl &> /dev/null; then
            curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /etc/apt/keyrings/trivy.gpg
        else
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /etc/apt/keyrings/trivy.gpg
        fi
        $SUDO chmod a+r /etc/apt/keyrings/trivy.gpg
        echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null
        $SUDO apt-get update
        $SUDO apt-get install -y trivy
        success "Trivy installed."
    else
        info "Trivy is already installed."
    fi

    migrate_trivy_keyring

    # Install RustScan (optional fast port scanner)
    if ! command -v rustscan &> /dev/null; then
        if apt_pkg_available "rustscan"; then
            info "Installing RustScan via APT..."
            $SUDO apt-get install -y rustscan
            success "RustScan installed."
        else
            info "Installing RustScan from GitHub release..."
            arch="$(uname -m)"

            asset_url=""
            asset_name=""
            # Try to use the GitHub API to find a suitable asset (best-effort).
            if command -v jq &> /dev/null; then
                release_json="$(fetch_github_release_json "$RUSTSCAN_REPO" "$RUSTSCAN_VERSION" || true)"
                if [ -n "$release_json" ]; then
                    if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
                        for pat in '^rustscan\\.deb\\.zip$' '^x86_64-linux-rustscan\\.tar\\.gz(\\.1)?\\.zip$' '^x86-linux-rustscan\\.zip$'; do
                            asset_url="$(pick_release_asset_url "$release_json" "$pat")"
                            if [ -n "$asset_url" ]; then
                                break
                            fi
                        done
                    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
                        for pat in '^aarch64-linux-rustscan\\.zip$' '^arm64-linux-rustscan\\.zip$'; do
                            asset_url="$(pick_release_asset_url "$release_json" "$pat")"
                            if [ -n "$asset_url" ]; then
                                break
                            fi
                        done
                    fi
                fi
            fi

            # Fallback: direct URLs (avoids GitHub API rate limits / jq issues).
            if [ -z "$asset_url" ]; then
                tags=("$RUSTSCAN_VERSION")
                if [[ "$RUSTSCAN_VERSION" != v* ]]; then
                    tags+=("v${RUSTSCAN_VERSION}")
                fi
                candidates=()
                if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
                    for tag in "${tags[@]}"; do
                        base="https://github.com/${RUSTSCAN_REPO}/releases/download/${tag}"
                        candidates+=("${base}/rustscan.deb.zip")
                        candidates+=("${base}/x86_64-linux-rustscan.tar.gz.zip")
                        candidates+=("${base}/x86_64-linux-rustscan.tar.gz.1.zip")
                    done
                elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
                    for tag in "${tags[@]}"; do
                        base="https://github.com/${RUSTSCAN_REPO}/releases/download/${tag}"
                        candidates+=("${base}/aarch64-linux-rustscan.zip")
                        candidates+=("${base}/arm64-linux-rustscan.zip")
                    done
                else
                    warn "Unsupported architecture for RustScan installer: $arch (skipping)"
                    return 0
                fi

                tmp_probe="$(mktemp -d)"
                for url in "${candidates[@]}"; do
                    name="$(basename "$url")"
                    if download_url_to_tmp "$url" "$tmp_probe" "$name"; then
                        asset_url="$url"
                        asset_name="$name"
                        break
                    fi
                done
                rm -rf "$tmp_probe"
            fi

            if [ -z "$asset_url" ]; then
                warn "Could not find a suitable RustScan release asset for arch=$arch in repo=$RUSTSCAN_REPO (version=$RUSTSCAN_VERSION)."
                warn "Try installing manually: https://github.com/${RUSTSCAN_REPO}/releases"
                return 0
            fi

            if [ -z "$asset_name" ]; then
                asset_name="$(basename "$asset_url")"
            fi

            tmpdir="$(mktemp -d)"
            download_url_to_tmp "$asset_url" "$tmpdir" "$asset_name" || true

            if [ ! -s "${tmpdir}/${asset_name}" ]; then
                warn "Failed to download RustScan package (${asset_name}). You may need to install it manually."
                rm -rf "$tmpdir"
            else
                # Asset types:
                # - rustscan.deb.zip -> contains a .deb
                # - x86_64-linux-rustscan.tar.gz.zip -> zip containing a tar.gz (which contains rustscan)
                # - aarch64-linux-rustscan.zip -> zip containing rustscan binary
                unzip -q "${tmpdir}/${asset_name}" -d "${tmpdir}/rustscan" || true

                deb_path="$(find "${tmpdir}/rustscan" -maxdepth 3 -type f -name '*.deb' | head -n 1)"
                if [ -n "$deb_path" ]; then
                    info "Installing RustScan .deb package..."
                    $SUDO dpkg -i "$deb_path" || $SUDO apt-get -f install -y
                    rm -rf "$tmpdir"
                else
                    tgz_path="$(find "${tmpdir}/rustscan" -maxdepth 3 -type f -name '*.tar.gz' | head -n 1)"
                    if [ -n "$tgz_path" ]; then
                        tar -xzf "$tgz_path" -C "${tmpdir}/rustscan" || true
                    fi
                    bin_path="$(find "${tmpdir}/rustscan" -maxdepth 4 -type f -name rustscan | head -n 1)"
                    if [ -z "$bin_path" ]; then
                        warn "RustScan archive did not contain a 'rustscan' binary (skipping)."
                        rm -rf "$tmpdir"
                    else
                        $SUDO install -m 0755 "$bin_path" /usr/local/bin/rustscan
                        rm -rf "$tmpdir"
                    fi
                fi

                if command -v rustscan &> /dev/null; then
                    success "RustScan installed."
                else
                    warn "RustScan install attempted, but rustscan is still not on PATH."
                fi
            fi
        fi
    else
        info "RustScan is already installed."
    fi

    # Install WPScan (WordPress scanner) - fallback to gem if not in APT
    if ! command -v wpscan &> /dev/null; then
        if apt_pkg_available "wpscan"; then
            info "WPScan will be installed via APT (handled in install_apt_deps)."
        else
            info "Installing WPScan via Ruby gem (fallback)..."
            # Install Ruby development packages required for native extensions
            info "Installing Ruby and build dependencies for WPScan..."
            $SUDO apt-get install -y ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev libyajl-dev || true

            if command -v gem &> /dev/null; then
                $SUDO gem install wpscan --no-document || warn "Failed to install WPScan via gem. Install manually: sudo gem install wpscan"
                if command -v wpscan &> /dev/null; then
                    success "WPScan installed via gem."
                else
                    warn "WPScan gem installed but not found on PATH. Try: sudo gem install wpscan"
                fi
            else
                warn "Ruby gem not available; cannot install WPScan. Install manually."
            fi
        fi
    else
        info "WPScan is already installed."
    fi

    # Install theHarvester (OSINT tool) - install from GitHub (PyPI package is outdated placeholder)
    if ! command -v theHarvester &> /dev/null && ! command -v theharvester &> /dev/null; then
        if apt_pkg_available "theharvester"; then
            info "theHarvester will be installed via APT (handled in install_apt_deps)."
        else
            info "Installing theHarvester from GitHub..."
            local theharvester_dir="/opt/theHarvester"

            # Install Python dependencies for theHarvester
            $SUDO apt-get install -y python3-pip python3-venv python3-dev || true

            if [ -d "$theharvester_dir" ]; then
                info "Updating existing theHarvester installation..."
                (cd "$theharvester_dir" && $SUDO git pull --ff-only) || warn "Failed to update theHarvester."
            else
                $SUDO git clone https://github.com/laramies/theHarvester.git "$theharvester_dir" || {
                    warn "Failed to clone theHarvester. Install manually: https://github.com/laramies/theHarvester"
                }
            fi

            if [ -d "$theharvester_dir" ]; then
                # Install dependencies in the system or create a wrapper
                if [ -f "$theharvester_dir/requirements.txt" ]; then
                    info "Installing theHarvester Python dependencies..."
                    $SUDO pip3 install -r "$theharvester_dir/requirements.txt" --break-system-packages 2>/dev/null || \
                    $SUDO pip3 install -r "$theharvester_dir/requirements.txt" || true
                fi

                # Create wrapper script
                $SUDO tee /usr/local/bin/theHarvester > /dev/null << 'HARVESTER_EOF'
#!/bin/bash
cd /opt/theHarvester
python3 theHarvester.py "$@"
HARVESTER_EOF
                $SUDO chmod +x /usr/local/bin/theHarvester
                $SUDO ln -sf /usr/local/bin/theHarvester /usr/local/bin/theharvester 2>/dev/null || true

                if command -v theHarvester &> /dev/null; then
                    success "theHarvester installed."
                else
                    warn "theHarvester installed to /opt but wrapper not working. Run manually: cd /opt/theHarvester && python3 theHarvester.py"
                fi
            fi
        fi
    else
        info "theHarvester is already installed."
    fi

    # Install CrackMapExec/NetExec (AD/Windows post-exploitation)
    if ! command -v crackmapexec &> /dev/null && ! command -v netexec &> /dev/null && ! command -v cme &> /dev/null && ! command -v nxc &> /dev/null; then
        info "Installing CrackMapExec/NetExec..."

        # Install system dependencies required by NetExec/CME
        info "Installing system dependencies for NetExec..."
        $SUDO apt-get install -y python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev \
            libkrb5-dev krb5-user libpq-dev build-essential pipx || true

        # Ensure pipx is available and configured
        if ! command -v pipx &> /dev/null; then
            info "Installing pipx..."
            $SUDO apt-get install -y pipx || pip3 install --user pipx --break-system-packages 2>/dev/null || pip3 install --user pipx || true
        fi

        # Ensure pipx path is set
        if command -v pipx &> /dev/null; then
            pipx ensurepath 2>/dev/null || true
            export PATH="$PATH:$HOME/.local/bin:/root/.local/bin"

            info "Installing NetExec via pipx (this may take a while)..."
            # NetExec is the actively maintained fork of CrackMapExec
            # Try with verbose output to see errors
            if pipx install netexec; then
                success "NetExec installed via pipx."
            else
                info "NetExec install failed, trying git-based install..."
                # Try installing from git directly
                if pipx install git+https://github.com/Pennyw0rth/NetExec.git; then
                    success "NetExec installed via pipx from GitHub."
                elif pipx install crackmapexec; then
                    success "CrackMapExec installed via pipx."
                else
                    warn "pipx install failed. Trying pip3 with --break-system-packages..."
                    # Final fallback: pip3 to system
                    if pip3 install netexec --break-system-packages; then
                        success "NetExec installed via pip3."
                    elif pip3 install git+https://github.com/Pennyw0rth/NetExec.git --break-system-packages; then
                        success "NetExec installed via pip3 from GitHub."
                    else
                        warn "All NetExec installation methods failed."
                        warn "Install manually: pipx install git+https://github.com/Pennyw0rth/NetExec.git"
                    fi
                fi
            fi
        else
            # Fallback to pip with --break-system-packages for Ubuntu 24.04+
            info "pipx not available, trying pip3..."
            if pip3 install netexec --break-system-packages; then
                success "NetExec installed via pip3."
            elif pip3 install git+https://github.com/Pennyw0rth/NetExec.git --break-system-packages; then
                success "NetExec installed via pip3 from GitHub."
            else
                warn "Failed to install NetExec/CrackMapExec via pip."
                warn "Install manually: pip3 install git+https://github.com/Pennyw0rth/NetExec.git --break-system-packages"
            fi
        fi

        # Check if installation succeeded
        if command -v netexec &> /dev/null || command -v nxc &> /dev/null; then
            success "NetExec installed and available."
        elif command -v crackmapexec &> /dev/null || command -v cme &> /dev/null; then
            success "CrackMapExec installed and available."
        elif [ -f "$HOME/.local/bin/netexec" ] || [ -f "$HOME/.local/bin/nxc" ]; then
            success "NetExec installed to ~/.local/bin (add to PATH: export PATH=\$PATH:\$HOME/.local/bin)"
        else
            warn "CrackMapExec/NetExec not found on PATH after install."
            warn "Try: pipx install netexec && pipx ensurepath"
        fi
    else
        info "CrackMapExec/NetExec is already installed."
    fi

    # Install enum4linux-ng (optional SMB enumeration helper)
    if ! command -v enum4linux-ng &> /dev/null && ! command -v enum4linux &> /dev/null; then
        info "Installing enum4linux-ng from GitHub..."
        # Dependencies used by enum4linux-ng
        ENUM_DEPS=(
            smbclient
            samba-common-bin
            python3-impacket
            python3-ldap3
            python3-yaml
        )
        ENUM_INSTALL=()
        for pkg in "${ENUM_DEPS[@]}"; do
            if apt_pkg_available "$pkg"; then
                ENUM_INSTALL+=("$pkg")
            fi
        done
        if [ "${#ENUM_INSTALL[@]}" -gt 0 ]; then
            $SUDO apt-get install -y "${ENUM_INSTALL[@]}"
        fi

        tmpdir="$(mktemp -d)"
        script_url=""
        for ref in "$ENUM4LINUX_NG_VERSION" "main" "master"; do
            url="https://raw.githubusercontent.com/${ENUM4LINUX_NG_REPO}/${ref}/enum4linux-ng.py"
            if download_url_to_tmp "$url" "$tmpdir" "enum4linux-ng.py"; then
                script_url="$url"
                break
            fi
        done

        if [ -n "$script_url" ]; then
            $SUDO install -m 0755 "${tmpdir}/enum4linux-ng.py" /usr/local/bin/enum4linux-ng
            success "enum4linux-ng installed."
        else
            warn "Failed to download enum4linux-ng script. Install manually: https://github.com/${ENUM4LINUX_NG_REPO}"
        fi
        rm -rf "$tmpdir"
    else
        info "enum4linux-ng/enum4linux already installed."
    fi
}

# 4. Python Environment
setup_python_env() {
    info "Setting up Python virtual environment..."
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    info "Installing Python dependencies from requirements.txt..."
    pip install --upgrade pip
    pip install -r requirements.txt
    
    success "Python environment ready."
}

install_optional_pdf_export() {
    if [ "$SUPABASH_PDF_EXPORT" = "1" ]; then
        info "Optional PDF export install requested via SUPABASH_PDF_EXPORT=1"
    else
        read -p "Install optional PDF/HTML report export deps (WeasyPrint)? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Skipping optional PDF/HTML export dependencies."
            return 0
        fi
    fi

    info "Installing system libraries for WeasyPrint..."
    WEASY_DEPS=(
        libcairo2
        libpango-1.0-0
        libpangocairo-1.0-0
        libpangoft2-1.0-0
        libgdk-pixbuf-2.0-0
        shared-mime-info
        fonts-dejavu-core
    )

    WEASY_INSTALL=()
    WEASY_MISSING=()
    for pkg in "${WEASY_DEPS[@]}"; do
        if apt_pkg_available "$pkg"; then
            WEASY_INSTALL+=("$pkg")
        else
            WEASY_MISSING+=("$pkg")
        fi
    done

    if [ "${#WEASY_INSTALL[@]}" -gt 0 ]; then
        $SUDO apt-get install -y "${WEASY_INSTALL[@]}"
    fi
    if [ "${#WEASY_MISSING[@]}" -gt 0 ]; then
        warn "Some WeasyPrint dependencies were not found in APT and were skipped: ${WEASY_MISSING[*]}"
    fi

    if [ ! -d "venv" ]; then
        warn "venv/ not found; creating Python environment first."
        setup_python_env
    fi
    source venv/bin/activate

    # Python packages: WeasyPrint + Markdown->HTML converter
    info "Installing Python packages for PDF export (weasyprint, markdown)..."
    if python3 -c "import weasyprint" >/dev/null 2>&1; then
        info "WeasyPrint is already installed in this venv."
    else
        pip install weasyprint
    fi
    if python3 -c "import markdown" >/dev/null 2>&1; then
        info "markdown is already installed in this venv."
    else
        pip install markdown
    fi

    success "Optional PDF/HTML export dependencies installed."
}

# 5. Global Entry Point
setup_symlink() {
    info "Creating global 'supabash' command..."
    
    # Create a wrapper script
    cat <<EOF > supabash_runner
#!/bin/bash
# Get the directory where the script is stored, resolving symlinks
SOURCE=\${BASH_SOURCE[0]}
while [ -L "\$SOURCE" ]; do # resolve \$SOURCE until the file is no longer a symlink
  DIR=\$( cd -P "\$( dirname "\$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=\$(readlink "\$SOURCE")
  [[ \$SOURCE != /* ]] && SOURCE=\$DIR/\$SOURCE # if \$SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR=\$( cd -P "\$( dirname "\$SOURCE" )" >/dev/null 2>&1 && pwd )

# Activate venv and run python module
source "\$DIR/venv/bin/activate"
export PYTHONPATH="\$DIR/src:\$PYTHONPATH"
python3 -m supabash "\$@"
EOF

    chmod +x supabash_runner
    
    # Link it to /usr/local/bin
    if [ -L "/usr/local/bin/supabash" ]; then
        $SUDO rm /usr/local/bin/supabash
    fi
    $SUDO ln -s "$(pwd)/supabash_runner" /usr/local/bin/supabash
    
    success "Symlink created. You can now run 'supabash' from anywhere."
}

# Main Execution
main() {
    echo -e "${BOLD}Supabash Installer${RESET}"
    echo "=================="
    
    detect_os
    
    # Ask for confirmation before installing system packages
    read -p "This script will install system packages and modify your system. Continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Aborted by user."
        exit 0
    fi

    install_apt_deps
    install_external_tools
    setup_python_env
    install_optional_pdf_export
    setup_symlink
    
    echo
    echo -e "${GREEN}Installation Complete!${RESET}"
    echo "Try running: supabash --help"
}

main
