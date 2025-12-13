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

apt_pkg_available() {
    apt-cache show "$1" >/dev/null 2>&1
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
        nikto
        sqlmap
        hydra
        gobuster
        whatweb
        sslscan
        dnsenum
        enum4linux
        # Add other standard tools here
    )

    INSTALL=()
    MISSING=()
    for pkg in "${DEPENDENCIES[@]}"; do
        if apt_pkg_available "$pkg"; then
            INSTALL+=("$pkg")
            continue
        fi
        if [[ "$pkg" == "enum4linux" ]]; then
            if apt_pkg_available "enum4linux-ng"; then
                warn "Package 'enum4linux' not found; using 'enum4linux-ng' instead."
                INSTALL+=("enum4linux-ng")
                continue
            fi
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
    # Install Nuclei (ProjectDiscovery)
    if ! command -v nuclei &> /dev/null; then
        info "Installing Nuclei..."
        # Download latest release binary (simplified for amd64 linux)
        wget -q https://github.com/projectdiscovery/nuclei/releases/download/v2.9.8/nuclei_2.9.8_linux_amd64.zip
        unzip -q nuclei_2.9.8_linux_amd64.zip
        sudo mv nuclei /usr/local/bin/
        rm nuclei_2.9.8_linux_amd64.zip
        success "Nuclei installed."
    else
        info "Nuclei is already installed."
    fi

    # Install Trivy (Container Scanner)
    if ! command -v trivy &> /dev/null; then
        info "Installing Trivy..."
        $SUDO apt-get install -y wget apt-transport-https gnupg lsb-release
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO apt-key add -
        echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | $SUDO tee -a /etc/apt/sources.list.d/trivy.list
        $SUDO apt-get update
        $SUDO apt-get install -y trivy
        success "Trivy installed."
    else
        info "Trivy is already installed."
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
        sudo rm /usr/local/bin/supabash
    fi
    sudo ln -s "$(pwd)/supabash_runner" /usr/local/bin/supabash
    
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
    setup_symlink
    
    echo
    echo -e "${GREEN}Installation Complete!${RESET}"
    echo "Try running: supabash --help"
}

main
