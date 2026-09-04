#!/bin/bash

# Supabash Installer
# Installs dependencies, sets up the environment, and configures the CLI.

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOL_SPEC_MANIFEST="${TOOL_SPEC_MANIFEST:-${SCRIPT_DIR}/src/supabash/data/tool_specs.v1.json}"

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
BLUE="\033[34m"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

NUCLEI_VERSION="${NUCLEI_VERSION:-}"
NUCLEI_REPO="${NUCLEI_REPO:-projectdiscovery/nuclei}"
RUSTSCAN_VERSION="${RUSTSCAN_VERSION:-}"
RUSTSCAN_REPO="${RUSTSCAN_REPO:-bee-san/RustScan}"
HTTPX_VERSION="${HTTPX_VERSION:-}"
HTTPX_REPO="${HTTPX_REPO:-projectdiscovery/httpx}"
SUBFINDER_VERSION="${SUBFINDER_VERSION:-}"
SUBFINDER_REPO="${SUBFINDER_REPO:-projectdiscovery/subfinder}"
KATANA_VERSION="${KATANA_VERSION:-}"
KATANA_REPO="${KATANA_REPO:-projectdiscovery/katana}"
TRIVY_VERSION="${TRIVY_VERSION:-}"
TRIVY_REPO="${TRIVY_REPO:-aquasecurity/trivy}"
ENUM4LINUX_NG_VERSION="${ENUM4LINUX_NG_VERSION:-}"
ENUM4LINUX_NG_REPO="${ENUM4LINUX_NG_REPO:-cddmp/enum4linux-ng}"
THEHARVESTER_VERSION="${THEHARVESTER_VERSION:-}"
NETEXEC_VERSION="${NETEXEC_VERSION:-}"
PROWLER_VERSION="${PROWLER_VERSION:-}"
BROWSER_USE_VERSION="${BROWSER_USE_VERSION:-}"
WPSCAN_VERSION="${WPSCAN_VERSION:-}"
MANAGED_PYTHON_312=""
# Optional: update nuclei templates for the invoking (non-root) user after install
SUPABASH_UPDATE_NUCLEI_TEMPLATES="${SUPABASH_UPDATE_NUCLEI_TEMPLATES:-1}"
# Healthy existing tools are retained; this flag also refreshes healthy versioned tools.
SUPABASH_UPGRADE_TOOLS="${SUPABASH_UPGRADE_TOOLS:-0}"
# Optional: install PDF/HTML report export dependencies (WeasyPrint)
SUPABASH_PDF_EXPORT="${SUPABASH_PDF_EXPORT:-0}"

# Optional manual installers (fallbacks for GitHub asset detection)
install_via_go() {
    local name="$1"
    local module="$2"
    local version="$3"
    local go_binary existing_path

    validate_tool_spec_manifest || return 1
    existing_path="$(tool_registry_resolve_executable "$name" || true)"
    if should_retain_existing_tool "$name" "$existing_path" "$name"; then
        return 0
    fi
    go_binary="$(command -v go 2>/dev/null || true)"
    if [ -z "$go_binary" ]; then
        warn "Go toolchain not found; cannot install ${name} via go install."
        return 1
    fi

    local go_version="${version:-latest}"
    if [ "$go_version" != "latest" ] && [[ "$go_version" != v* ]]; then
        go_version="v${go_version}"
    fi
    local mod_ref="$module@${go_version}"
    info "Installing ${name} via go install (${mod_ref})..."

    local tmpdir
    tmpdir="$(run_as_invoking_user mktemp -d "/tmp/supabash-${name}-go.XXXXXX")"
    local gobin
    gobin="${tmpdir}/bin"
    run_as_invoking_user mkdir -p "$gobin"

    local install_log
    install_log="$(mktemp "${TMPDIR:-/tmp}/supabash-${name}-go.XXXXXX.log")"
    if ! run_as_invoking_user env GO111MODULE=on GOBIN="$gobin" \
        "$go_binary" install -v "$mod_ref" >"$install_log" 2>&1; then
        warn "go install failed for ${name}. See ${install_log}"
        rm -rf "$tmpdir"
        return 1
    fi
    rm -f "$install_log"

    if [ ! -x "${gobin}/${name}" ]; then
        warn "go install finished but ${name} binary not found at ${gobin}/${name}."
        rm -rf "$tmpdir"
        return 1
    fi

    $SUDO install -m 0755 "${gobin}/${name}" "/usr/local/bin/${name}"
    rm -rf "$tmpdir"
    if tool_registry_resolve_executable "$name" >/dev/null 2>&1; then
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

invoking_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
        echo "${SUDO_USER}"
    else
        id -un
    fi
}

invoking_home() {
    local user
    user="$(invoking_user)"
    getent passwd "$user" | cut -d: -f6
}

run_as_invoking_user() {
    local user
    user="$(invoking_user)"
    if [ "$user" = "$(id -un)" ]; then
        "$@"
    else
        sudo -u "$user" -H "$@"
    fi
}

run_as_invoking_user_shell() {
    local user home cmd
    user="$(invoking_user)"
    home="$(invoking_home)"
    cmd="$1"
    if [ "$user" = "$(id -un)" ]; then
        HOME="$home" bash -lc "export PATH=\"$home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"; $cmd"
    else
        sudo -u "$user" -H bash -lc "export PATH=\"$home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"; $cmd"
    fi
}

invoking_user_has_command() {
    local name="$1"
    run_as_invoking_user_shell "command -v '$name' >/dev/null 2>&1"
}

ensure_invoking_user_pipx() {
    if ! invoking_user_has_command pipx; then
        info "Installing pipx..."
        $SUDO apt-get install -y pipx || \
            run_as_invoking_user python3 -m pip install --user pipx --break-system-packages 2>/dev/null || \
            run_as_invoking_user python3 -m pip install --user pipx || true
    fi
    if invoking_user_has_command pipx; then
        run_as_invoking_user_shell "pipx ensurepath >/dev/null 2>&1 || true" || true
        return 0
    fi
    return 1
}

ensure_invoking_user_uv() {
    if invoking_user_has_command uv; then
        return 0
    fi
    ensure_invoking_user_pipx || true
    if invoking_user_has_command pipx && run_as_invoking_user_shell "pipx install --force uv"; then
        return 0
    fi
    run_as_invoking_user python3 -m pip install --user uv --break-system-packages 2>/dev/null || \
        run_as_invoking_user python3 -m pip install --user uv || true
    invoking_user_has_command uv
}

ensure_managed_python_312() {
    if [ -n "$MANAGED_PYTHON_312" ]; then
        return 0
    fi
    ensure_invoking_user_uv || return 1
    run_as_invoking_user_shell "uv python install 3.12 >/dev/null" || return 1
    MANAGED_PYTHON_312="$(run_as_invoking_user_shell "uv python find 3.12" 2>/dev/null | tail -n 1)"
    if [[ ! "$MANAGED_PYTHON_312" =~ ^/[A-Za-z0-9._/+:-]+$ ]] \
        || ! run_as_invoking_user_shell "test -x '$MANAGED_PYTHON_312'"; then
        MANAGED_PYTHON_312=""
        return 1
    fi
}

check_codex_setup() {
    local version auth_status
    if ! invoking_user_has_command codex; then
        warn "Codex CLI is not installed; the optional Codex planner will remain unavailable."
        warn "Install Codex separately, run 'codex login', then verify with 'supabash doctor --codex'."
        return 0
    fi

    version="$(run_as_invoking_user_shell "codex --version" 2>/dev/null | head -n 1 || true)"
    if [ -n "$version" ]; then
        success "Codex CLI detected (${version})."
    else
        warn "Codex CLI was found but its version could not be read."
    fi

    auth_status="$(run_as_invoking_user_shell "codex login status" 2>&1 || true)"
    if grep -qi "logged in using chatgpt" <<<"$auth_status"; then
        success "Codex is authenticated with ChatGPT."
    else
        warn "Codex is not authenticated with a ChatGPT subscription for Supabash."
        warn "Run 'codex login', then 'supabash doctor --codex' from a standalone terminal."
    fi
}

tool_recommended_version() {
    local tool_id="$1"
    local value=""
    validate_tool_spec_manifest || return 1
    if ! value="$(
        jq -er --arg id "$tool_id" \
            '.tools[] | select(.id == $id) | .recommended_version // empty' \
            -- "$TOOL_SPEC_MANIFEST" 2>/dev/null
    )"; then
        warn "ToolSpec registry has no tested version for ${tool_id}."
        return 1
    fi
    printf '%s\n' "$value"
}

validate_tool_spec_manifest() {
    local python_binary
    if ! command -v jq >/dev/null 2>&1; then
        warn "Cannot validate the ToolSpec registry because jq is unavailable."
        return 1
    fi
    if [ ! -f "$TOOL_SPEC_MANIFEST" ] || [ ! -r "$TOOL_SPEC_MANIFEST" ]; then
        warn "ToolSpec registry is missing or unreadable: ${TOOL_SPEC_MANIFEST}"
        return 1
    fi
    if ! jq -e '
        def nonempty_string: type == "string" and length > 0;
        def nonempty_strings:
            type == "array" and length > 0 and all(.[]; nonempty_string);
        def safe_version:
            type == "string" and test("^[vV]?[0-9][0-9A-Za-z._+-]*$");
        (.schema_version == 1)
        and (.registry_version | nonempty_string)
        and (.tools | type == "array" and length > 0)
        and (([.tools[].id] | length) == ([.tools[].id] | unique | length))
        and all(.tools[];
            (.id | type == "string" and test("^[a-z0-9][a-z0-9_-]*$"))
            and (.doctor_required | type == "boolean")
            and ((.recommended_version == null) or (.recommended_version | safe_version))
            and (.executables | type == "array")
            and (if .doctor_required then (.executables | length > 0) else true end)
            and all(.executables[];
                (.candidates | nonempty_strings)
                and (.health_probe | type == "object")
                and (.health_probe.argv | nonempty_strings)
                and (.health_probe.argv[0] == "{executable}")
                and (.health_probe.success_exit_codes
                    | type == "array" and length > 0
                    and all(.[]; type == "number" and floor == . and . >= 0 and . <= 255))
                and (.health_probe.timeout_seconds
                    | type == "number" and floor == . and . >= 1 and . <= 30)
            )
        )
    ' -- "$TOOL_SPEC_MANIFEST" >/dev/null 2>&1; then
        warn "ToolSpec registry failed installer validation: ${TOOL_SPEC_MANIFEST}"
        return 1
    fi
    python_binary="$(command -v python3 2>/dev/null || true)"
    if [ -z "$python_binary" ]; then
        warn "Cannot validate the full ToolSpec schema because Python 3 is unavailable."
        return 1
    fi
    if ! PYTHONPATH="${SCRIPT_DIR}/src" \
        "$python_binary" -c \
        'import sys; from pathlib import Path; from supabash.tool_registry import load_tool_registry; load_tool_registry(Path(sys.argv[1]))' \
        "$TOOL_SPEC_MANIFEST" >/dev/null 2>&1; then
        warn "ToolSpec registry failed installer validation: ${TOOL_SPEC_MANIFEST}"
        return 1
    fi
}

tool_registry_resolve_executable() {
    local tool_id="$1" candidate resolved
    validate_tool_spec_manifest || return 1
    while IFS= read -r candidate; do
        resolved="$(command -v "$candidate" 2>/dev/null || true)"
        if [[ "$resolved" == /* ]] && [ -f "$resolved" ] && [ -x "$resolved" ]; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done < <(
        jq -r --arg id "$tool_id" '
            .tools[]
            | select(.id == $id or (((.aliases // []) | index($id)) != null))
            | .executables[0].candidates[]
        ' -- "$TOOL_SPEC_MANIFEST"
    )
    return 1
}

tool_registry_health_check() {
    local tool_id="$1" executable="$2" run_for_invoking_user="${3:-0}"
    local timeout_seconds return_code allowed=0 log_file
    local -a probe_argv success_codes
    validate_tool_spec_manifest || return 1
    mapfile -t probe_argv < <(
        jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].health_probe.argv[]' -- "$TOOL_SPEC_MANIFEST"
    )
    [ "${#probe_argv[@]}" -gt 0 ] || return 1
    for index in "${!probe_argv[@]}"; do
        if [ "${probe_argv[$index]}" = "{executable}" ]; then
            probe_argv[$index]="$executable"
        fi
    done
    mapfile -t success_codes < <(
        jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].health_probe.success_exit_codes[]' -- "$TOOL_SPEC_MANIFEST"
    )
    timeout_seconds="$(
        jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].health_probe.timeout_seconds' -- "$TOOL_SPEC_MANIFEST"
    )"
    log_file="$(mktemp "${TMPDIR:-/tmp}/supabash-health-${tool_id}.XXXXXX.log")"
    if [ "$run_for_invoking_user" = "1" ]; then
        if run_as_invoking_user timeout "$timeout_seconds" "${probe_argv[@]}" >"$log_file" 2>&1; then
            return_code=0
        else
            return_code=$?
        fi
    elif timeout "$timeout_seconds" "${probe_argv[@]}" >"$log_file" 2>&1; then
        return_code=0
    else
        return_code=$?
    fi
    for code in "${success_codes[@]}"; do
        if [ "$return_code" = "$code" ]; then
            allowed=1
            break
        fi
    done
    if grep -Eqi \
        'traceback \(most recent call last\)|modulenotfounderror:|importerror:|error while loading shared libraries|cannot open shared object file|command not found' \
        "$log_file"; then
        allowed=0
    fi
    rm -f "$log_file"
    [ "$allowed" = "1" ]
}

resolve_invoking_user_command() {
    local candidate resolved
    for candidate in "$@"; do
        resolved="$(run_as_invoking_user_shell "command -v '$candidate'" 2>/dev/null | tail -n 1 || true)"
        if [[ "$resolved" == /* ]] && [ -x "$resolved" ]; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done
    return 1
}

should_retain_existing_tool() {
    local tool_id="$1" executable="${2:-}" display_name="${3:-$1}"
    local run_for_invoking_user="${4:-0}"
    if [ -z "$executable" ] || [ "$SUPABASH_UPGRADE_TOOLS" = "1" ]; then
        return 1
    fi
    if tool_registry_health_check "$tool_id" "$executable" "$run_for_invoking_user"; then
        info "${display_name} is already installed and healthy."
        return 0
    fi
    warn "${display_name} is present but failed its startup probe; attempting repair."
    return 1
}

load_tool_versions() {
    validate_tool_spec_manifest || error "Cannot continue with an invalid ToolSpec registry."
    NUCLEI_VERSION="${NUCLEI_VERSION:-$(tool_recommended_version nuclei)}"
    RUSTSCAN_VERSION="${RUSTSCAN_VERSION:-$(tool_recommended_version rustscan)}"
    HTTPX_VERSION="${HTTPX_VERSION:-$(tool_recommended_version httpx)}"
    SUBFINDER_VERSION="${SUBFINDER_VERSION:-$(tool_recommended_version subfinder)}"
    KATANA_VERSION="${KATANA_VERSION:-$(tool_recommended_version katana)}"
    TRIVY_VERSION="${TRIVY_VERSION:-$(tool_recommended_version trivy)}"
    ENUM4LINUX_NG_VERSION="${ENUM4LINUX_NG_VERSION:-$(tool_recommended_version enum4linux_ng)}"
    THEHARVESTER_VERSION="${THEHARVESTER_VERSION:-$(tool_recommended_version theharvester)}"
    NETEXEC_VERSION="${NETEXEC_VERSION:-$(tool_recommended_version crackmapexec)}"
    PROWLER_VERSION="${PROWLER_VERSION:-$(tool_recommended_version prowler)}"
    BROWSER_USE_VERSION="${BROWSER_USE_VERSION:-$(tool_recommended_version browser_use)}"
    WPSCAN_VERSION="${WPSCAN_VERSION:-$(tool_recommended_version wpscan)}"
    local variable value
    for variable in NUCLEI_VERSION RUSTSCAN_VERSION HTTPX_VERSION SUBFINDER_VERSION \
        KATANA_VERSION TRIVY_VERSION ENUM4LINUX_NG_VERSION THEHARVESTER_VERSION \
        NETEXEC_VERSION PROWLER_VERSION BROWSER_USE_VERSION WPSCAN_VERSION; do
        value="${!variable}"
        if [ -z "$value" ] || [[ ! "$value" =~ ^[vV]?[0-9][0-9A-Za-z._+-]*$ ]]; then
            error "Invalid version value in ${variable}."
        fi
    done
}

install_browser_use() {
    local browser_user browser_path pipx_python=""
    validate_tool_spec_manifest || return 1
    browser_user="$(invoking_user)"
    browser_path="$(resolve_invoking_user_command browser-use browser_use || true)"
    if should_retain_existing_tool browser_use "$browser_path" browser-use 1; then
        return 0
    fi

    info "Installing/repairing browser-use ${BROWSER_USE_VERSION} for ${browser_user}..."
    $SUDO apt-get install -y python3-pip python3-venv python3-dev pipx || true
    if ensure_managed_python_312; then
        pipx_python="--python '$MANAGED_PYTHON_312'"
    else
        warn "Could not provision Python 3.12; browser-use installation may be incompatible with the distro Python."
    fi
    if ensure_invoking_user_pipx; then
        if run_as_invoking_user_shell "pipx install --force ${pipx_python} 'browser-use==${BROWSER_USE_VERSION}'"; then
            success "browser-use installed via pipx."
        else
            warn "pipx install failed. Trying an invoking-user pip fallback..."
            run_as_invoking_user python3 -m pip install --user "browser-use[cli]==${BROWSER_USE_VERSION}" --break-system-packages || true
        fi
    else
        info "pipx not available for ${browser_user}; trying invoking-user pip..."
        run_as_invoking_user python3 -m pip install --user "browser-use[cli]==${BROWSER_USE_VERSION}" --break-system-packages || true
    fi

    # browser-use runtime bootstrap expects uv/uvx.
    ensure_invoking_user_uv || warn "uv/uvx is unavailable; browser runtime setup may fail."

    # Install browser runtime assets only when installing or repairing the CLI.
    if invoking_user_has_command browser-use; then
        info "Installing browser-use runtime assets (this may take a while)..."
        local browser_log
        browser_log="$(mktemp "${TMPDIR:-/tmp}/supabash-browser-use.XXXXXX.log")"
        if ! run_as_invoking_user_shell "browser-use install" >"$browser_log" 2>&1; then
            warn "browser-use runtime install failed. See ${browser_log}"
            warn "Run manually: browser-use install"
        else
            rm -f "$browser_log"
        fi
    elif invoking_user_has_command browser_use; then
        info "Installing browser_use runtime assets (this may take a while)..."
        local browser_log
        browser_log="$(mktemp "${TMPDIR:-/tmp}/supabash-browser-use.XXXXXX.log")"
        if ! run_as_invoking_user_shell "browser_use install" >"$browser_log" 2>&1; then
            warn "browser_use runtime install failed. See ${browser_log}"
            warn "Run manually: browser_use install"
        else
            rm -f "$browser_log"
        fi
    fi

    if invoking_user_has_command browser-use || invoking_user_has_command browser_use; then
        success "browser-use CLI available."
    else
        warn "browser-use install attempted, but command was not found on PATH."
        warn "Try: pipx install 'browser-use==${BROWSER_USE_VERSION}' && pipx ensurepath && browser-use install"
    fi
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

    # A requested version is a compatibility contract. Never silently install a
    # different "latest" release when the requested tag cannot be found.
    url="https://api.github.com/repos/${repo}/releases/tags/${version}"
    if curl -fsSL "$url" 2>/dev/null; then
        return 0
    fi
    if [[ "$version" != v* ]]; then
        url="https://api.github.com/repos/${repo}/releases/tags/v${version}"
        if curl -fsSL "$url" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
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

verify_release_asset_checksum() {
    local release_json="$1"
    local asset_name="$2"
    local tmpdir="$3"
    local checksum_url checksum_name expected actual

    checksum_url="$(pick_release_asset_url "$release_json" '.*checksums.*\.txt$')"
    if [ -z "$checksum_url" ]; then
        warn "Release does not publish a checksum file for ${asset_name}."
        return 1
    fi

    checksum_name="$(basename "$checksum_url")"
    if ! download_url_to_tmp "$checksum_url" "$tmpdir" "$checksum_name"; then
        warn "Could not download checksum file for ${asset_name}."
        return 1
    fi

    expected="$(awk -v name="$asset_name" '$2 == name || $2 == "*" name {print $1; exit}' "${tmpdir}/${checksum_name}")"
    if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]]; then
        warn "Checksum file does not contain a SHA-256 entry for ${asset_name}."
        return 1
    fi
    actual="$(sha256sum "${tmpdir}/${asset_name}" | awk '{print $1}')"
    if [ "${actual,,}" != "${expected,,}" ]; then
        warn "SHA-256 verification failed for ${asset_name}."
        return 1
    fi
    success "Verified SHA-256 checksum for ${asset_name}."
}

install_github_zip_binary() {
    local name="$1"
    local repo="$2"
    local version="$3"
    local pat_amd64="$4"
    local pat_arm64="$5"
    local require_checksum="${6:-0}" existing_path

    validate_tool_spec_manifest || return 1
    existing_path="$(tool_registry_resolve_executable "$name" || true)"
    if should_retain_existing_tool "$name" "$existing_path" "$name"; then
        return 0
    fi

    if [ -n "$existing_path" ]; then
        info "Updating ${name} from its tested GitHub release..."
    else
        info "Installing ${name} from GitHub release..."
    fi
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

    if [ "$require_checksum" = "1" ] && ! verify_release_asset_checksum "$release_json" "$asset_name" "$tmpdir"; then
        warn "Refusing to install unverified ${name} release asset."
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
    if tool_registry_resolve_executable "$name" >/dev/null 2>&1; then
        success "${name} installed."
        return 0
    fi
    warn "${name} install attempted, but ${name} is still not on PATH."
    return 1
}

install_trivy_release() {
    local existing_path
    validate_tool_spec_manifest || return 1
    existing_path="$(command -v trivy 2>/dev/null || true)"
    if should_retain_existing_tool trivy "$existing_path" Trivy; then
        return 0
    fi

    local arch release_version tag asset_name checksum_name base_url tmpdir expected actual
    arch="$(uname -m)"
    release_version="${TRIVY_VERSION#v}"
    tag="v${release_version}"
    case "$arch" in
        x86_64|amd64) asset_name="trivy_${release_version}_Linux-64bit.deb" ;;
        aarch64|arm64) asset_name="trivy_${release_version}_Linux-ARM64.deb" ;;
        *)
            warn "Unsupported architecture for Trivy release installer: ${arch}"
            return 1
            ;;
    esac
    checksum_name="trivy_${release_version}_checksums.txt"
    base_url="https://github.com/${TRIVY_REPO}/releases/download/${tag}"
    tmpdir="$(mktemp -d)"

    if ! download_url_to_tmp "${base_url}/${asset_name}" "$tmpdir" "$asset_name" \
        || ! download_url_to_tmp "${base_url}/${checksum_name}" "$tmpdir" "$checksum_name"; then
        warn "Failed to download the tested Trivy ${release_version} release and checksum."
        rm -rf "$tmpdir"
        return 1
    fi
    expected="$(awk -v name="$asset_name" '$2 == name || $2 == "*" name {print $1; exit}' "${tmpdir}/${checksum_name}")"
    actual="$(sha256sum "${tmpdir}/${asset_name}" | awk '{print $1}')"
    if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]] || [ "${actual,,}" != "${expected,,}" ]; then
        warn "Refusing to install Trivy: SHA-256 verification failed for ${asset_name}."
        rm -rf "$tmpdir"
        return 1
    fi
    success "Verified SHA-256 checksum for ${asset_name}."

    if ! $SUDO dpkg -i "${tmpdir}/${asset_name}"; then
        $SUDO apt-get -f install -y || true
        $SUDO dpkg -i "${tmpdir}/${asset_name}" || {
            rm -rf "$tmpdir"
            return 1
        }
    fi
    rm -rf "$tmpdir"
    command -v trivy >/dev/null 2>&1
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
        postgresql-client
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
        aircrack-ng
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
    validate_tool_spec_manifest || return 1
    install_exploitdb

    # Install a compatibility-tested Nuclei engine. ProjectDiscovery releases
    # publish checksums, which are required before replacing the executable.
    if ! install_github_zip_binary "nuclei" "$NUCLEI_REPO" "$NUCLEI_VERSION" '^nuclei_.*_linux_amd64\.zip$' '^nuclei_.*_linux_arm64\.zip$' 1; then
        warn "Falling back to go install for Nuclei (if Go is available)."
        install_via_go "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" "$NUCLEI_VERSION" || true
    fi

    # Templates evolve independently from the engine, so refresh them on every
    # installer run (unless explicitly disabled), not just on first install.
    if command -v nuclei &> /dev/null; then
        if [ "$SUPABASH_UPDATE_NUCLEI_TEMPLATES" = "1" ]; then
            info "Updating Nuclei templates for the invoking user (best-effort)..."
            run_as_invoking_user_shell "nuclei -update-templates >/dev/null 2>&1" || \
                warn "Nuclei template update failed; run: nuclei -update-templates"
        else
            info "Skipping Nuclei template update (set SUPABASH_UPDATE_NUCLEI_TEMPLATES=1 to enable)."
        fi
    fi

    # Install httpx (ProjectDiscovery HTTP probing)
    if ! install_github_zip_binary "httpx" "$HTTPX_REPO" "$HTTPX_VERSION" '^httpx_.*_linux_amd64\.zip$' '^httpx_.*_linux_arm64\.zip$' 1; then
        warn "Falling back to go install for httpx (if Go is available)."
        install_via_go "httpx" "github.com/projectdiscovery/httpx/cmd/httpx" "$HTTPX_VERSION" || true
    fi

    # Install subfinder (ProjectDiscovery subdomain discovery)
    if ! install_github_zip_binary "subfinder" "$SUBFINDER_REPO" "$SUBFINDER_VERSION" '^subfinder_.*_linux_amd64\.zip$' '^subfinder_.*_linux_arm64\.zip$' 1; then
        warn "Falling back to go install for subfinder (if Go is available)."
        install_via_go "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "$SUBFINDER_VERSION" || true
    fi

    # Install katana (ProjectDiscovery crawler)
    if ! install_github_zip_binary "katana" "$KATANA_REPO" "$KATANA_VERSION" '^katana_.*_linux_amd64\.zip$' '^katana_.*_linux_arm64\.zip$' 1; then
        warn "Falling back to go install for katana (if Go is available)."
        install_via_go "katana" "github.com/projectdiscovery/katana/cmd/katana" "$KATANA_VERSION" || true
    fi

    # Install Trivy from its compatibility-tested, checksummed release. Keep the
    # official APT repository as a fresh-install fallback when GitHub is unavailable.
    if ! install_trivy_release; then
        warn "Could not install the tested Trivy ${TRIVY_VERSION} release."
    fi
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
    fi

    migrate_trivy_keyring

    # Install RustScan (optional fast port scanner)
    local rustscan_path
    rustscan_path="$(command -v rustscan 2>/dev/null || true)"
    if ! should_retain_existing_tool rustscan "$rustscan_path" RustScan; then
            info "Installing RustScan from its tested GitHub release..."
            arch="$(uname -m)"

            asset_url=""
            asset_name=""
            # Try to use the GitHub API to find a suitable asset (best-effort).
            if command -v jq &> /dev/null; then
                release_json="$(fetch_github_release_json "$RUSTSCAN_REPO" "$RUSTSCAN_VERSION" || true)"
                if [ -n "$release_json" ]; then
                    if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
                        for pat in '^rustscan\.deb\.zip$' '^x86_64-linux-rustscan\.tar\.gz(\.1)?\.zip$' '^x86-linux-rustscan\.zip$'; do
                            asset_url="$(pick_release_asset_url "$release_json" "$pat")"
                            if [ -n "$asset_url" ]; then
                                break
                            fi
                        done
                    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
                        for pat in '^aarch64-linux-rustscan\.zip$' '^arm64-linux-rustscan\.zip$'; do
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

    # Install WPScan (WordPress scanner) - fallback to gem if not in APT
    local wpscan_path
    wpscan_path="$(command -v wpscan 2>/dev/null || true)"
    if ! should_retain_existing_tool wpscan "$wpscan_path" WPScan; then
            info "Installing WPScan ${WPSCAN_VERSION} via Ruby gem..."
            # Install Ruby development packages required for native extensions
            info "Installing Ruby and build dependencies for WPScan..."
            $SUDO apt-get install -y ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev libyajl-dev || true

            if command -v gem &> /dev/null; then
                $SUDO gem install wpscan -v "$WPSCAN_VERSION" --no-document || \
                    warn "Failed to install WPScan via gem. Install manually: sudo gem install wpscan -v ${WPSCAN_VERSION}"
                if command -v wpscan &> /dev/null; then
                    success "WPScan installed via gem."
                else
                    warn "WPScan gem installed but not found on PATH. Try: sudo gem install wpscan -v ${WPSCAN_VERSION}"
                fi
            else
                warn "Ruby gem not available; cannot install WPScan. Install manually."
            fi
    fi

    # theHarvester 4.x uses pyproject/uv and Python >=3.12. Install it in an
    # isolated, invoking-user tool environment instead of modifying system
    # Python or relying on the removed requirements.txt layout.
    local theharvester_path
    theharvester_path="$(resolve_invoking_user_command theHarvester theharvester || true)"
    if ! should_retain_existing_tool theharvester "$theharvester_path" theHarvester 1; then
        if [ -n "$theharvester_path" ] && [ "$SUPABASH_UPGRADE_TOOLS" = "1" ]; then
            info "Updating theHarvester ${THEHARVESTER_VERSION} in an isolated uv tool environment..."
        else
            info "Installing/repairing theHarvester ${THEHARVESTER_VERSION} in an isolated uv tool environment..."
        fi
        if ensure_invoking_user_uv && run_as_invoking_user_shell \
            "uv tool install --force --python 3.12 'git+https://github.com/laramies/theHarvester.git@${THEHARVESTER_VERSION}'"; then
            if run_as_invoking_user_shell "theHarvester -h >/dev/null 2>&1 || theharvester -h >/dev/null 2>&1"; then
                success "theHarvester installed and passed its health probe."
            else
                warn "theHarvester installation completed but its health probe failed."
            fi
        else
            warn "Failed to install theHarvester with uv."
            warn "Run: uv tool install --force --python 3.12 'git+https://github.com/laramies/theHarvester.git@${THEHARVESTER_VERSION}'"
        fi
    fi

    # Install CrackMapExec/NetExec (AD/Windows post-exploitation)
    local netexec_path
    netexec_path="$(resolve_invoking_user_command netexec nxc crackmapexec cme || true)"
    if ! should_retain_existing_tool crackmapexec "$netexec_path" "CrackMapExec/NetExec" 1; then
        info "Installing CrackMapExec/NetExec..."
        local netexec_ref="$NETEXEC_VERSION"
        local netexec_python=""
        if [[ "$netexec_ref" != v* ]]; then
            netexec_ref="v${netexec_ref}"
        fi
        if ensure_managed_python_312; then
            netexec_python="--python '$MANAGED_PYTHON_312'"
        fi

        # Install system dependencies required by NetExec/CME
        info "Installing system dependencies for NetExec..."
        $SUDO apt-get install -y python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev \
            libkrb5-dev krb5-user libpq-dev build-essential pipx || true

        if ensure_invoking_user_pipx; then
            info "Installing NetExec via pipx (this may take a while)..."
            local pipx_force=""
            if [ "$SUPABASH_UPGRADE_TOOLS" = "1" ]; then
                pipx_force="--force"
            fi
            # NetExec is not published on PyPI. Install the compatibility-tested
            # upstream tag rather than silently tracking the mutable main branch.
            if run_as_invoking_user_shell \
                "pipx install ${pipx_force} ${netexec_python} 'git+https://github.com/Pennyw0rth/NetExec.git@${netexec_ref}'"; then
                success "NetExec ${NETEXEC_VERSION} installed via pipx from GitHub."
            else
                warn "pipx install failed. Trying an invoking-user pip fallback..."
                if run_as_invoking_user python3 -m pip install --user \
                    "git+https://github.com/Pennyw0rth/NetExec.git@${netexec_ref}" \
                    --break-system-packages; then
                    success "NetExec ${NETEXEC_VERSION} installed via pip from GitHub."
                else
                    warn "All NetExec installation methods failed."
                    warn "Run: pipx install 'git+https://github.com/Pennyw0rth/NetExec.git@${netexec_ref}'"
                fi
            fi
        else
            info "pipx not available, trying invoking-user pip..."
            if run_as_invoking_user python3 -m pip install --user \
                "git+https://github.com/Pennyw0rth/NetExec.git@${netexec_ref}" \
                --break-system-packages; then
                success "NetExec ${NETEXEC_VERSION} installed via pip from GitHub."
            else
                warn "Failed to install NetExec/CrackMapExec via pip."
                warn "Run: pipx install 'git+https://github.com/Pennyw0rth/NetExec.git@${netexec_ref}'"
            fi
        fi

        # Check if installation succeeded
        if run_as_invoking_user_shell "command -v netexec >/dev/null 2>&1 || command -v nxc >/dev/null 2>&1"; then
            success "NetExec installed and available."
        elif run_as_invoking_user_shell "command -v crackmapexec >/dev/null 2>&1 || command -v cme >/dev/null 2>&1"; then
            success "CrackMapExec installed and available."
        else
            warn "CrackMapExec/NetExec not found on PATH after install."
            warn "Try: pipx install 'git+https://github.com/Pennyw0rth/NetExec.git@${netexec_ref}' && pipx ensurepath"
        fi
    fi

    # Install ScoutSuite (multi-cloud audit)
    if ! run_as_invoking_user_shell "command -v scout >/dev/null 2>&1 || command -v ScoutSuite >/dev/null 2>&1"; then
        info "Installing ScoutSuite..."
        $SUDO apt-get install -y python3-pip python3-venv python3-dev || true
        if ensure_invoking_user_pipx; then
            local pipx_force=""
            if [ "$SUPABASH_UPGRADE_TOOLS" = "1" ]; then
                pipx_force="--force"
            fi
            run_as_invoking_user_shell "pipx install ${pipx_force} scoutsuite" || \
                run_as_invoking_user_shell "pipx install ${pipx_force} ScoutSuite" || true
        else
            run_as_invoking_user python3 -m pip install --user scoutsuite --break-system-packages 2>/dev/null || \
                run_as_invoking_user python3 -m pip install --user scoutsuite || true
        fi
        if run_as_invoking_user_shell "command -v scout >/dev/null 2>&1 || command -v ScoutSuite >/dev/null 2>&1"; then
            success "ScoutSuite installed."
        else
            warn "ScoutSuite install attempted, but 'scout' is not on PATH. Try: pipx install scoutsuite"
        fi
    else
        info "ScoutSuite is already installed."
    fi

    # Install Prowler (AWS audits)
    local prowler_path
    prowler_path="$(resolve_invoking_user_command prowler || true)"
    if ! should_retain_existing_tool prowler "$prowler_path" Prowler 1; then
        info "Installing Prowler..."
        $SUDO apt-get install -y python3-pip python3-venv python3-dev || true
        if ensure_invoking_user_pipx; then
            local pipx_force="" prowler_python=""
            if [ "$SUPABASH_UPGRADE_TOOLS" = "1" ]; then
                pipx_force="--force"
            fi
            if ensure_managed_python_312; then
                prowler_python="--python '$MANAGED_PYTHON_312'"
            fi
            run_as_invoking_user_shell "pipx install ${pipx_force} ${prowler_python} 'prowler==${PROWLER_VERSION}'" || true
        else
            run_as_invoking_user python3 -m pip install --user "prowler==${PROWLER_VERSION}" --break-system-packages 2>/dev/null || \
                run_as_invoking_user python3 -m pip install --user "prowler==${PROWLER_VERSION}" || true
        fi
        if invoking_user_has_command prowler; then
            success "Prowler installed."
        else
            warn "Prowler install attempted, but 'prowler' is not on PATH. Try: pipx install prowler"
        fi
    fi

    # Install browser-use CLI (browser-driven authenticated checks in agentic mode).
    install_browser_use

    # Install enum4linux-ng (optional SMB enumeration helper)
    local enum4linux_path
    enum4linux_path="$(command -v enum4linux-ng 2>/dev/null || command -v enum4linux 2>/dev/null || true)"
    if ! should_retain_existing_tool enum4linux_ng "$enum4linux_path" enum4linux-ng; then
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
        enum_ref="$ENUM4LINUX_NG_VERSION"
        if [[ "$enum_ref" != v* ]]; then
            enum_ref="v${enum_ref}"
        fi
        url="https://raw.githubusercontent.com/${ENUM4LINUX_NG_REPO}/${enum_ref}/enum4linux-ng.py"
        if download_url_to_tmp "$url" "$tmpdir" "enum4linux-ng.py"; then
            script_url="$url"
        fi

        if [ -n "$script_url" ]; then
            $SUDO install -m 0755 "${tmpdir}/enum4linux-ng.py" /usr/local/bin/enum4linux-ng
            success "enum4linux-ng installed."
        else
            warn "Failed to download enum4linux-ng script. Install manually: https://github.com/${ENUM4LINUX_NG_REPO}"
        fi
        rm -rf "$tmpdir"
    fi
}

# 4. Python Environment
setup_python_env() {
    local project_dir
    project_dir="$(pwd)"
    info "Setting up Python virtual environment..."
    if [ ! -d "venv" ]; then
        run_as_invoking_user python3 -m venv "${project_dir}/venv"
    fi

    info "Installing Python dependencies from requirements.txt..."
    run_as_invoking_user "${project_dir}/venv/bin/python" -m pip install --upgrade pip
    run_as_invoking_user "${project_dir}/venv/bin/python" -m pip install -r "${project_dir}/requirements.txt"
    
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
    # Python packages: WeasyPrint + Markdown->HTML converter
    info "Installing Python packages for PDF export (weasyprint, markdown)..."
    if run_as_invoking_user "$(pwd)/venv/bin/python" -c "import weasyprint" >/dev/null 2>&1; then
        info "WeasyPrint is already installed in this venv."
    else
        run_as_invoking_user "$(pwd)/venv/bin/python" -m pip install weasyprint
    fi
    if run_as_invoking_user "$(pwd)/venv/bin/python" -c "import markdown" >/dev/null 2>&1; then
        info "markdown is already installed in this venv."
    else
        run_as_invoking_user "$(pwd)/venv/bin/python" -m pip install markdown
    fi

    success "Optional PDF/HTML export dependencies installed."
}

verify_required_tool_health() {
    local failures=() tool_id resolved candidate timeout_seconds return_code log_file allowed
    local recommended_version detected_version lowest_version
    local -a candidates probe_argv success_codes
    validate_tool_spec_manifest || return 1

    while IFS= read -r tool_id; do
        resolved=""
        mapfile -t candidates < <(
            jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].candidates[]' -- "$TOOL_SPEC_MANIFEST"
        )
        for candidate in "${candidates[@]}"; do
            if command -v "$candidate" >/dev/null 2>&1; then
                resolved="$(command -v "$candidate")"
                break
            fi
        done
        if [ -z "$resolved" ]; then
            warn "Required tool ${tool_id} is missing."
            failures+=("$tool_id")
            continue
        fi

        mapfile -t probe_argv < <(
            jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].health_probe.argv[]' -- "$TOOL_SPEC_MANIFEST"
        )
        for index in "${!probe_argv[@]}"; do
            if [ "${probe_argv[$index]}" = "{executable}" ]; then
                probe_argv[$index]="$resolved"
            fi
        done
        mapfile -t success_codes < <(
            jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].health_probe.success_exit_codes[]' -- "$TOOL_SPEC_MANIFEST"
        )
        timeout_seconds="$(
            jq -r --arg id "$tool_id" '.tools[] | select(.id == $id) | .executables[0].health_probe.timeout_seconds' -- "$TOOL_SPEC_MANIFEST"
        )"
        log_file="$(mktemp "${TMPDIR:-/tmp}/supabash-health-${tool_id}.XXXXXX.log")"
        if timeout "$timeout_seconds" "${probe_argv[@]}" >"$log_file" 2>&1; then
            return_code=0
        else
            return_code=$?
        fi
        allowed=0
        for code in "${success_codes[@]}"; do
            if [ "$return_code" = "$code" ]; then
                allowed=1
                break
            fi
        done
        if [ "$allowed" != "1" ] || grep -Eqi \
            'traceback \(most recent call last\)|modulenotfounderror:|importerror:|error while loading shared libraries|cannot open shared object file|command not found' \
            "$log_file"; then
            warn "Required tool ${tool_id} failed its safe startup probe (exit ${return_code})."
            failures+=("$tool_id")
        else
            recommended_version="$(
                jq -r --arg id "$tool_id" \
                    '.tools[] | select(.id == $id) | .recommended_version // empty' \
                    -- "$TOOL_SPEC_MANIFEST"
            )"
            if [ -n "$recommended_version" ]; then
                detected_version="$(
                    grep -Eo '[vV]?[0-9]+([.][0-9]+)+' "$log_file" \
                        | head -n 1 \
                        | sed -E 's/^[vV]//'
                )"
                recommended_version="${recommended_version#v}"
                recommended_version="${recommended_version#V}"
                if [ -z "$detected_version" ]; then
                    warn "Required tool ${tool_id} passed startup but its version could not be verified."
                    failures+=("$tool_id")
                else
                    lowest_version="$(
                        printf '%s\n%s\n' "$detected_version" "$recommended_version" \
                            | sort -V \
                            | head -n 1
                    )"
                    if [ "$lowest_version" != "$recommended_version" ]; then
                        warn "Required tool ${tool_id} ${detected_version} is older than the tested baseline ${recommended_version}."
                        warn "Rerun with ./install.sh --upgrade-tools to update versioned tools."
                        failures+=("$tool_id")
                    fi
                fi
            fi
        fi
        rm -f "$log_file"
    done < <(jq -r '.tools[] | select(.doctor_required == true) | .id' -- "$TOOL_SPEC_MANIFEST")

    if [ "${#failures[@]}" -gt 0 ]; then
        warn "Required tool verification failed: ${failures[*]}"
        return 1
    fi
    success "Required Supabash tools passed startup health checks."
}

verify_versioned_tool_upgrades() {
    if [ "$SUPABASH_UPGRADE_TOOLS" != "1" ]; then
        return 0
    fi
    local doctor_command doctor_json project_python
    local -a failures
    doctor_json="$(mktemp "${TMPDIR:-/tmp}/supabash-upgrade-doctor.XXXXXX.json")"
    project_python="$(pwd)/venv/bin/python"
    printf -v doctor_command \
        'env PYTHONPATH=%q %q -m supabash doctor --deep --json' \
        "${SCRIPT_DIR}/src" "$project_python"
    run_as_invoking_user_shell "$doctor_command" >"$doctor_json" 2>/dev/null || true
    if ! jq -e '.checks | type == "array"' "$doctor_json" >/dev/null 2>&1; then
        warn "Could not parse deep-doctor results after tool upgrades."
        rm -f "$doctor_json"
        return 1
    fi
    mapfile -t failures < <(
        jq -r '
          .checks[]
          | select((.name | startswith("bin:")) and (.details.recommended_version != null))
          | select((.ok != true) or ((.details.detected_version // "") == ""))
          | "\(.details.tool // .name): \(.message)"
        ' "$doctor_json"
    )
    rm -f "$doctor_json"
    if [ "${#failures[@]}" -gt 0 ]; then
        warn "One or more versioned tool upgrades could not be verified:"
        printf '  - %s\n' "${failures[@]}"
        return 1
    fi
    success "Versioned tools match or exceed their ToolSpec baselines."
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

# Use Supabash's interpreter without modifying the caller's scanner PATH.
export PYTHONPATH="\$DIR/src\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\$DIR/venv/bin/python" -m supabash "\$@"
EOF

    chmod +x supabash_runner
    if [ "$(id -u)" -eq 0 ] && [ "$(invoking_user)" != "root" ]; then
        $SUDO chown "$(invoking_user):$(id -gn "$(invoking_user)")" supabash_runner
    fi
    
    # Link it to /usr/local/bin
    if [ -L "/usr/local/bin/supabash" ]; then
        $SUDO rm /usr/local/bin/supabash
    fi
    $SUDO ln -s "$(pwd)/supabash_runner" /usr/local/bin/supabash
    
    success "Symlink created. You can now run 'supabash' from anywhere."
}

# Main Execution
usage() {
    cat <<'EOF'
Usage: ./install.sh [--upgrade-tools] [--yes]

  --upgrade-tools  Reinstall/update versioned third-party tools to ToolSpec baselines.
  --yes            Accept the system-modification confirmation.
  -h, --help       Show this help.

Environment equivalents:
  SUPABASH_UPGRADE_TOOLS=1
  SUPABASH_UPDATE_NUCLEI_TEMPLATES=0
  SUPABASH_PDF_EXPORT=1
EOF
}

main() {
    local assume_yes=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --upgrade-tools)
                SUPABASH_UPGRADE_TOOLS=1
                ;;
            --yes)
                assume_yes=1
                ;;
            -h|--help)
                usage
                return 0
                ;;
            *)
                error "Unknown installer option: $1"
                ;;
        esac
        shift
    done

    # Make relative project paths deterministic even when the installer is
    # invoked as /path/to/install.sh from another working directory.
    cd "$SCRIPT_DIR"

    echo -e "${BOLD}Supabash Installer${RESET}"
    echo "=================="
    
    detect_os
    
    # Ask for confirmation before installing system packages
    if [ "$assume_yes" != "1" ]; then
        read -p "This script will install system packages and modify your system. Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Aborted by user."
            exit 0
        fi
    fi

    install_apt_deps
    load_tool_versions
    install_external_tools
    setup_python_env
    # Codex authentication is user-owned and must never be automated by this installer.
    check_codex_setup
    install_optional_pdf_export
    verify_required_tool_health || error "Installation finished with missing or broken required tools."
    verify_versioned_tool_upgrades || error "One or more requested tool upgrades failed verification."
    setup_symlink
    
    echo
    echo -e "${GREEN}Installation Complete!${RESET}"
    echo "Try running: supabash --help"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
