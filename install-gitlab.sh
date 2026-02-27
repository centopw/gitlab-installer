#!/usr/bin/env bash
# =============================================================================
#  GitLab CE — Single-File Automated Installer v3.0
#  Ubuntu 22.04 | Pangolin Reverse Proxy | Separate Git SSH
#
#  Usage:
#    sudo bash install-gitlab.sh              # interactive
#    sudo bash install-gitlab.sh --fresh      # wipe state, start over
#    sudo bash install-gitlab.sh --verify-only # health check only
#
#  One-liner:
#    bash <(curl -fsSL https://your-host/install-gitlab.sh)
#
#  Unattended (env vars):
#    GITLAB_DOMAIN=git.example.com GIT_SSH_PORT=2222 \
#    DISABLE_PROMETHEUS=true DISABLE_PUMA_WORKERS=true \
#    sudo bash install-gitlab.sh --unattended
# =============================================================================

# ── Self-re-exec guard ────────────────────────────────────────────────────────
# If the shebang fails (downloaded file, wrong default shell, etc.) and this
# script is run under /bin/sh, this POSIX-safe line detects it and re-launches
# the script explicitly under bash. Must stay before "set -euo pipefail".
# shellcheck disable=SC2317
[ -z "${BASH_VERSION:-}" ] && exec bash "$0" "$@"

# Require bash 4.0+ (Ubuntu 22.04 ships bash 5.x — this is a sanity check)
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: bash 4.0 or newer is required (found bash ${BASH_VERSION})." >&2
    echo "       Install it with: sudo apt-get install bash" >&2
    exit 1
fi

set -euo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 1 — COLOURS, LOGGING & BASIC HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

LOG_FILE="/var/log/gitlab-installer.log"
STATE_FILE="/var/tmp/gitlab-install-state"
GITLAB_RB="/etc/gitlab/gitlab.rb"
GITLAB_CTL="/usr/bin/gitlab-ctl"

touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/gitlab-installer.log"

_log()    { echo -e "$*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$*"; }
info()    { _log "${CYAN}[INFO]${NC}    $*"; }
success() { _log "${GREEN}[OK]${NC}      $*"; }
warn()    { _log "${YELLOW}[WARN]${NC}    $*"; }
error()   { _log "${RED}[ERROR]${NC}   $*"; }
fatal()   { _log "${RED}${BOLD}[FATAL]${NC}   $*"; exit 1; }
step()    { _log ""; _log "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; _log "${BOLD}${BLUE}  $*${NC}"; _log "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; _log ""; }
hr()      { echo -e "${DIM}────────────────────────────────────────────────────────────${NC}"; }

state_done()  { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }
state_mark()  { echo "$1" >> "$STATE_FILE"; }
state_clear() { rm -f "$STATE_FILE"; info "State cleared — all steps will re-run."; }

UNATTENDED=false
for arg in "$@"; do
    case "$arg" in
        --unattended|-y) UNATTENDED=true ;;
        --fresh)         state_clear ;;
        --help|-h) echo "Usage: sudo bash $0 [--unattended] [--fresh] [--verify-only]"; exit 0 ;;
    esac
done

confirm() {
    local prompt="$1" default="${2:-n}"
    [[ "$UNATTENDED" == "true" ]] && { [[ "$default" == "y" ]] && return 0 || return 1; }
    echo -ne "${YELLOW}${prompt}${NC} [$([ "$default" = "y" ] && echo "Y/n" || echo "y/N")]: "
    read -r ans; ans="${ans:-$default}"
    [[ "${ans,,}" == "y" ]]
}

prompt_value() {
    local prompt="$1" var="$2" default="${3:-}"
    local current="${!var:-$default}"
    [[ "$UNATTENDED" == "true" ]] && { echo "$current"; return; }
    # Prompt goes to stderr so $() capture only gets the actual value
    if [[ -n "$current" ]]; then
        echo -ne "${YELLOW}[INPUT]${NC} ${prompt} [${CYAN}${current}${NC}]: " >&2
    else
        echo -ne "${YELLOW}[INPUT]${NC} ${prompt}: " >&2
    fi
    read -r val </dev/tty
    echo "${val:-$current}"
}

prompt_bool() {
    local prompt="$1" var="$2" default="${3:-false}"
    local current="${!var:-$default}"
    [[ "$UNATTENDED" == "true" ]] && { echo "$current"; return; }
    local d; [[ "$current" == "true" ]] && d="y" || d="n"
    echo -ne "${YELLOW}[INPUT]${NC} ${prompt} ${DIM}(y/n)${NC} [${CYAN}${d}${NC}]: " >&2
    read -r val </dev/tty; val="${val:-$d}"
    [[ "${val,,}" == "y" || "${val,,}" == "true" ]] && echo "true" || echo "false"
}

prompt_password() {
    [[ "$UNATTENDED" == "true" ]] && { echo "${SMTP_PASS:-}"; return; }
    echo -ne "${YELLOW}[INPUT]${NC} $1 ${DIM}(hidden)${NC}: " >&2
    read -rs val </dev/tty; echo "" >&2; echo "$val"
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 2 — OS & HARDWARE DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

detect_os() {
    OS_ID=""; OS_VERSION=""; OS_CODENAME=""; OS_PRETTY=""
    OS_ARCH=$(uname -m); OS_KERNEL=$(uname -r)
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="${ID:-}"; OS_VERSION="${VERSION_ID:-}"
        OS_CODENAME="${VERSION_CODENAME:-}"; OS_PRETTY="${PRETTY_NAME:-unknown}"
    fi
}

check_cpu()  { CPU_CORES=$(nproc 2>/dev/null || echo 1); (( CPU_CORES >= 4 )) && return 0; (( CPU_CORES >= 2 )) && return 2; return 1; }
check_ram()  { RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo); (( RAM_MB >= 7800 )) && return 0; (( RAM_MB >= 3800 )) && return 2; return 1; }
check_disk() { DISK_FREE_GB=$(df -BG / --output=avail 2>/dev/null | tail -1 | tr -d 'G' | tr -d ' '); (( DISK_FREE_GB >= 50 )) && return 0; (( DISK_FREE_GB >= 20 )) && return 2; return 1; }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 3 — EXISTING GITLAB DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

gitlab_is_installed()      { [[ "$(dpkg -l gitlab-ce 2>/dev/null | awk '/gitlab-ce/{print $1}')" == "ii" ]]; }
gitlab_installed_version() { dpkg -l gitlab-ce 2>/dev/null | awk '/gitlab-ce/{print $3}' | head -1; }

detect_gitlab_health() {
    GITLAB_HEALTH="none"; GITLAB_INSTALLED_VERSION=""; GITLAB_BROKEN_REASON=""
    if ! gitlab_is_installed; then
        { [[ -d "/var/opt/gitlab" ]] || [[ -f "$GITLAB_RB" ]]; } && \
            GITLAB_HEALTH="partial" && \
            GITLAB_BROKEN_REASON="Residual GitLab files exist but package is not installed"
        return
    fi
    GITLAB_INSTALLED_VERSION=$(gitlab_installed_version)
    [[ ! -x "$GITLAB_CTL" ]] && GITLAB_HEALTH="broken" && GITLAB_BROKEN_REASON="gitlab-ctl missing" && return
    [[ ! -f "$GITLAB_RB"  ]] && GITLAB_HEALTH="broken" && GITLAB_BROKEN_REASON="gitlab.rb missing"  && return
    local running; running=$(gitlab-ctl status 2>/dev/null | grep -c "^run:" || echo 0)
    (( running == 0 )) && GITLAB_HEALTH="broken" && GITLAB_BROKEN_REASON="No services running" && return
    local down=()
    for svc in nginx puma gitaly postgresql redis; do
        gitlab-ctl status 2>/dev/null | grep -q "down: ${svc}" && down+=("$svc")
    done
    (( ${#down[@]} > 0 )) && GITLAB_HEALTH="degraded" && GITLAB_BROKEN_REASON="Critical services down: ${down[*]}" && return
    GITLAB_HEALTH="healthy"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 4 — REPAIR ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ── Fix corrupted/empty gitlab-secrets.json ──────────────────────────────────
# A zero-byte or non-JSON secrets file causes every reconfigure to fail with:
#   Chef::Exceptions::JSON::ParseError: Top level JSON object must be a Hash or Array
# The file is auto-regenerated by reconfigure when absent — safe to remove/reset.
fix_corrupt_secrets() {
    local secrets_file="/etc/gitlab/gitlab-secrets.json"
    if [[ -f "$secrets_file" ]]; then
        # Check if file is empty or not valid JSON (must start with { or [)
        local first_char
        first_char=$(head -c1 "$secrets_file" 2>/dev/null || echo "")
        if [[ -z "$first_char" || ( "$first_char" != "{" && "$first_char" != "[" ) ]]; then
            warn "Corrupted secrets file detected: ${secrets_file}"
            warn "File size: $(wc -c < "$secrets_file") bytes, first char: '${first_char}'"
            local bak="${secrets_file}.corrupt.$(date +%Y%m%d_%H%M%S)"
            mv "$secrets_file" "$bak"
            warn "Moved corrupt file to: ${bak}"
            success "Secrets file cleared — GitLab will regenerate it on reconfigure."
            return 0
        else
            local size
            size=$(wc -c < "$secrets_file")
            success "Secrets file OK (${size} bytes, starts with valid JSON char)."
            return 1  # no fix needed
        fi
    fi
    return 1  # file does not exist, nothing to fix
}

repair_gitlab() {
    local mode="${1:-auto}"
    step "Repair Engine — Mode: ${mode}"
    case "$mode" in
        auto)
            info "Automatic repair sequence: dpkg-fix → reconfigure → restart"
            repair_gitlab dpkg-fix  || true
            repair_gitlab reconfigure && return 0
            repair_gitlab restart   && return 0
            warn "Auto-repair could not fully restore GitLab."; return 1 ;;
        dpkg-fix)
            info "Fixing dpkg state..."
            dpkg --configure -a 2>&1 | tee -a "$LOG_FILE" || true
            DEBIAN_FRONTEND=noninteractive apt-get install -f -y 2>&1 | tee -a "$LOG_FILE" || true
            success "dpkg repair done." ;;
        reconfigure)
            info "Checking for corrupted secrets file before reconfigure..."
            fix_corrupt_secrets || true
            info "Running gitlab-ctl reconfigure..."
            timeout 300 gitlab-ctl reconfigure 2>&1 | tee -a "$LOG_FILE" \
                && success "Reconfigure succeeded." || { error "Reconfigure failed."; return 1; } ;;
        restart)
            info "Stopping GitLab..."; gitlab-ctl stop 2>&1 | tee -a "$LOG_FILE" || true; sleep 3
            info "Starting GitLab..."; gitlab-ctl start 2>&1 | tee -a "$LOG_FILE" || true; sleep 5
            local r; r=$(gitlab-ctl status 2>/dev/null | grep -c "^run:" || echo 0)
            (( r > 0 )) && success "GitLab restarted (${r} services)." || { error "Restart failed."; return 1; } ;;
        purge-reinstall)
            warn "Will REMOVE gitlab-ce package and reinstall. Data in /var/opt/gitlab is PRESERVED."
            confirm "Type YES to confirm (destructive)" "n" || { info "Aborted."; return 1; }
            [[ -x "$GITLAB_CTL" ]] && \
                timeout 120 gitlab-backup create SKIP=uploads,builds,artifacts,registry \
                    2>&1 | tee -a "$LOG_FILE" || warn "Pre-purge backup failed — continuing."
            gitlab-ctl stop 2>&1 | tee -a "$LOG_FILE" || true
            DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y gitlab-ce 2>&1 | tee -a "$LOG_FILE"
            rm -rf /opt/gitlab/embedded/etc /opt/gitlab/sv 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y gitlab-ce 2>&1 | tee -a "$LOG_FILE" \
                || fatal "Reinstall failed. See ${LOG_FILE}."
            repair_gitlab reconfigure ;;
        *) error "Unknown repair mode: ${mode}"; return 1 ;;
    esac
}

open_repair_shell() {
    warn "Opening repair subshell. Type 'exit' to return."
    echo "Useful: gitlab-ctl status | reconfigure | restart | tail"
    bash --login
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 5 — COMPATIBILITY & PRE-FLIGHT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

run_preflight() {
    step "Pre-flight: Compatibility, OS & Existing Install Checks"
    local block=0 warnings=0
    detect_os

    # Root
    [[ $EUID -eq 0 ]] && success "Running as root." || { error "Must run as root: sudo bash $0"; ((block++)); }

    # OS type
    [[ "${OS_ID,,}" == "ubuntu" ]] && success "OS: ${OS_PRETTY}" || { error "Unsupported OS: ${OS_PRETTY}. Required: Ubuntu."; ((block++)); }

    # OS version
    case "$OS_VERSION" in
        "22.04") success "Ubuntu 22.04 — fully supported." ;;
        "20.04"|"24.04") warn "Ubuntu ${OS_VERSION} detected — targets 22.04, may work."; ((warnings++)) ;;
        *) error "Ubuntu ${OS_VERSION} not supported. Required: 22.04."; ((block++)) ;;
    esac

    # Architecture
    case "$OS_ARCH" in
        x86_64|aarch64) success "Architecture: ${OS_ARCH}" ;;
        *) error "Unsupported architecture: ${OS_ARCH}. Required: x86_64 or aarch64."; ((block++)) ;;
    esac

    # Virtualization (info only)
    command -v systemd-detect-virt &>/dev/null && {
        local virt; virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        [[ "$virt" != "none" ]] && success "Virtualization: ${virt} (supported)" || success "Bare metal"
    }

    # CPU
    check_cpu
    case $? in
        0) success "CPU cores: ${CPU_CORES}" ;;
        2) warn "CPU cores: ${CPU_CORES} (4+ recommended)"; ((warnings++)) ;;
        1) error "CPU cores: ${CPU_CORES} — minimum 2 required."; ((block++)) ;;
    esac

    # RAM
    check_ram
    case $? in
        0) success "RAM: ${RAM_MB} MB" ;;
        2) warn "RAM: ${RAM_MB} MB — below recommended 8 GB. Enable RAM-saving options."; ((warnings++)) ;;
        1) error "RAM: ${RAM_MB} MB — minimum 4 GB required. GitLab will OOM."; ((block++)) ;;
    esac

    # Disk
    check_disk
    case $? in
        0) success "Free disk: ${DISK_FREE_GB} GB" ;;
        2) warn "Free disk: ${DISK_FREE_GB} GB — below recommended 50 GB."; ((warnings++)) ;;
        1) error "Free disk: ${DISK_FREE_GB} GB — minimum 20 GB required."; ((block++)) ;;
    esac

    # Internet
    curl -s --max-time 10 https://packages.gitlab.com &>/dev/null \
        && success "Internet: packages.gitlab.com reachable." \
        || { error "Cannot reach packages.gitlab.com — check network/DNS."; ((block++)); }

    # Conflicting packages
    for pkg in apache2 nginx-full; do
        dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" && \
            { warn "Conflicting package: ${pkg} — may conflict with GitLab nginx."; ((warnings++)); }
    done

    # Port 80 conflict
    ss -tlnp 2>/dev/null | grep -q ':80 ' && {
        local h; h=$(ss -tlnp 2>/dev/null | grep ':80 ' | awk '{print $NF}' | head -1)
        warn "Port 80 already in use: ${h}"; ((warnings++))
    }

    # systemd state
    local sd; sd=$(systemctl is-system-running 2>/dev/null || echo "unknown")
    case "$sd" in
        running)     success "systemd: running" ;;
        degraded)    warn "systemd degraded — run 'systemctl --failed'"; ((warnings++)) ;;
        maintenance) error "systemd in maintenance mode. Fix before continuing."; ((block++)) ;;
        *)           warn "systemd state: ${sd}" ;;
    esac

    # Existing GitLab
    info "Checking for existing GitLab installation..."
    detect_gitlab_health
    case "$GITLAB_HEALTH" in
        none)
            success "No existing GitLab found — clean install."
            INSTALL_ACTION="fresh" ;;
        healthy)
            warn "GitLab ${GITLAB_INSTALLED_VERSION} already installed and healthy."
            echo ""; echo -e "  ${BOLD}Choose action:${NC}"
            echo -e "    ${CYAN}(r)${NC} Reconfigure only"; echo -e "    ${CYAN}(u)${NC} Upgrade to latest"
            echo -e "    ${CYAN}(v)${NC} Verify only";      echo -e "    ${CYAN}(q)${NC} Quit"
            if [[ "$UNATTENDED" == "true" ]]; then INSTALL_ACTION="reconfigure-only"
            else
                echo -ne "\n  Choice [r/u/v/q]: "; read -r ch
                case "${ch,,}" in r) INSTALL_ACTION="reconfigure-only" ;; u) INSTALL_ACTION="upgrade" ;; v) INSTALL_ACTION="verify-only" ;; *) info "Quitting."; exit 0 ;; esac
            fi ;;
        degraded)
            warn "GitLab ${GITLAB_INSTALLED_VERSION} DEGRADED: ${GITLAB_BROKEN_REASON}"
            echo ""; echo -e "  ${BOLD}Choose action:${NC}"
            echo -e "    ${CYAN}(a)${NC} Auto-repair then install"; echo -e "    ${CYAN}(r)${NC} Repair only"
            echo -e "    ${CYAN}(c)${NC} Continue anyway";          echo -e "    ${CYAN}(q)${NC} Quit"
            if [[ "$UNATTENDED" == "true" ]]; then repair_gitlab auto; INSTALL_ACTION="fresh"
            else
                echo -ne "\n  Choice [a/r/c/q]: "; read -r ch
                case "${ch,,}" in a) repair_gitlab auto; INSTALL_ACTION="fresh" ;; r) repair_gitlab auto; INSTALL_ACTION="verify-only" ;; c) INSTALL_ACTION="fresh" ;; *) info "Quitting."; exit 0 ;; esac
            fi ;;
        broken)
            error "GitLab ${GITLAB_INSTALLED_VERSION} BROKEN: ${GITLAB_BROKEN_REASON}"
            echo ""; echo -e "  ${BOLD}Choose repair:${NC}"
            echo -e "    ${CYAN}(a)${NC} Auto-repair";    echo -e "    ${CYAN}(p)${NC} Purge & reinstall"
            echo -e "    ${CYAN}(m)${NC} Repair shell";   echo -e "    ${CYAN}(q)${NC} Quit"
            if [[ "$UNATTENDED" == "true" ]]; then repair_gitlab auto; INSTALL_ACTION="reconfigure-only"
            else
                echo -ne "\n  Choice [a/p/m/q]: "; read -r ch
                case "${ch,,}" in a) repair_gitlab auto; INSTALL_ACTION="reconfigure-only" ;; p) repair_gitlab purge-reinstall; INSTALL_ACTION="reconfigure-only" ;; m) open_repair_shell ;; *) info "Quitting."; exit 0 ;; esac
            fi ;;
        partial)
            warn "Partial install detected: ${GITLAB_BROKEN_REASON}"
            confirm "Clean up residual files and do fresh install?" "y" && {
                apt-get remove --purge -y gitlab-ce 2>/dev/null || true
                dpkg --configure -a 2>/dev/null || true
                INSTALL_ACTION="fresh"
            } || { info "Quitting."; exit 0; } ;;
    esac

    # Verdict
    echo ""
    if (( block > 0 )); then
        echo -e "${RED}${BOLD}  ╔══════════════════════════════════════════════════════╗"
        echo -e "  ║  ✗  COMPATIBILITY CHECKS FAILED — CANNOT PROCEED    ║"
        echo -e "  ╚══════════════════════════════════════════════════════╝${NC}"
        fatal "Fix the errors above then re-run. Log: ${LOG_FILE}"
    elif (( warnings > 0 )); then
        echo -e "${YELLOW}${BOLD}  ╔══════════════════════════════════════════════════════╗"
        echo -e "  ║  ⚠  ${warnings} warning(s) — review before continuing        ║"
        echo -e "  ╚══════════════════════════════════════════════════════╝${NC}"
        confirm "Continue despite warnings?" "y" || { info "Aborted."; exit 0; }
    else
        echo -e "${GREEN}${BOLD}  ╔══════════════════════════════════════════════════════╗"
        echo -e "  ║  ✓  All pre-flight checks passed                     ║"
        echo -e "  ╚══════════════════════════════════════════════════════╝${NC}"
    fi
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 6 — CONFIGURATION WIZARD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

validate_domain() { [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; }
validate_port()   { local p="$1"; [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1024 && p <= 65535 && p != 22 && p != 80 && p != 443 )); }

run_config_wizard() {
    step "Configuration Wizard"
    [[ "$UNATTENDED" == "true" ]] && info "Unattended mode — using environment variables." \
                                  || echo -e "${DIM}Press Enter to accept defaults shown in [brackets].${NC}"

    # Domain
    echo ""; echo -e "${BOLD}── Domain ───────────────────────────────────────────────────${NC}"
    echo -e "${DIM}  The public FQDN Pangolin will expose this GitLab instance on.${NC}"
    while true; do
        GITLAB_DOMAIN=$(prompt_value "GitLab domain (FQDN)" "GITLAB_DOMAIN" "gitlab.example.com")
        validate_domain "$GITLAB_DOMAIN" && break || warn "'${GITLAB_DOMAIN}' is not a valid FQDN."
    done

    # Git SSH Port
    echo ""; echo -e "${BOLD}── Git SSH Port ──────────────────────────────────────────────${NC}"
    echo -e "${DIM}  Port for git clone/push over SSH. Must NOT be 22, 80 or 443.${NC}"
    while true; do
        GIT_SSH_PORT=$(prompt_value "Git SSH port" "GIT_SSH_PORT" "2222")
        validate_port "$GIT_SSH_PORT" && break || warn "Invalid port. Use 1024-65535, not 22/80/443."
    done

    # Pangolin
    echo ""; echo -e "${BOLD}── Pangolin / Reverse Proxy ──────────────────────────────────${NC}"
    echo -e "${DIM}  Pangolin proxies HTTPS externally → GitLab HTTP:80 internally.${NC}"
    PANGOLIN_INTERNAL_IP=$(prompt_value "Pangolin tunnel IP (blank = allow all RFC1918)" "PANGOLIN_INTERNAL_IP" "")
    ALLOW_DIRECT_HTTPS=$(prompt_bool  "Open port 443 in firewall too? (not needed if only Pangolin connects)" "ALLOW_DIRECT_HTTPS" "false")
    TRUSTED_PROXIES=$(prompt_value    "Trusted proxy CIDRs (comma-separated)" "TRUSTED_PROXIES" "127.0.0.1/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")

    # Backups
    echo ""; echo -e "${BOLD}── Backups ──────────────────────────────────────────────────${NC}"
    GITLAB_BACKUP_PATH=$(prompt_value "Backup directory"   "GITLAB_BACKUP_PATH" "/var/opt/gitlab/backups")
    BACKUP_KEEP_DAYS=$(prompt_value   "Days to keep backups" "BACKUP_KEEP_DAYS" "7")
    BACKUP_KEEP_TIME=$(( BACKUP_KEEP_DAYS * 86400 ))

    # Performance
    echo ""; echo -e "${BOLD}── Performance ──────────────────────────────────────────────${NC}"
    local ram_def="false"
    (( RAM_MB < 7800 )) && ram_def="true" && warn "Low RAM (${RAM_MB} MB) — RAM-saving options defaulting to ON."
    DISABLE_PROMETHEUS=$(prompt_bool "Disable Prometheus & Grafana? (saves ~500 MB RAM)" "DISABLE_PROMETHEUS" "$ram_def")
    DISABLE_PUMA_WORKERS=$(prompt_bool "Reduce Puma workers to 2? (saves ~300 MB RAM)" "DISABLE_PUMA_WORKERS" "$ram_def")

    # SMTP
    echo ""; echo -e "${BOLD}── SMTP / Email ─────────────────────────────────────────────${NC}"
    echo -e "${DIM}  Enables notifications and password resets.${NC}"
    SMTP_ENABLE=$(prompt_bool "Enable SMTP?" "SMTP_ENABLE" "false")
    if [[ "$SMTP_ENABLE" == "true" ]]; then
        SMTP_ADDRESS=$(prompt_value     "SMTP hostname"    "SMTP_ADDRESS"       "smtp.gmail.com")
        SMTP_PORT=$(prompt_value        "SMTP port"        "SMTP_PORT"          "587")
        SMTP_USER=$(prompt_value        "SMTP username"    "SMTP_USER"          "")
        SMTP_PASS=$(prompt_password     "SMTP password")
        SMTP_DOMAIN=$(prompt_value      "Mail domain"      "SMTP_DOMAIN"        "$GITLAB_DOMAIN")
        GITLAB_EMAIL_FROM=$(prompt_value "From address"    "GITLAB_EMAIL_FROM"  "gitlab@${GITLAB_DOMAIN}")
        SMTP_TLS=$(prompt_bool          "Enable STARTTLS?" "SMTP_TLS"           "true")
    else
        SMTP_ADDRESS=""; SMTP_PORT="587"; SMTP_USER=""; SMTP_PASS=""
        SMTP_DOMAIN=""; GITLAB_EMAIL_FROM=""; SMTP_TLS="false"
    fi

    # Summary
    echo ""
    echo -e "${BOLD}Configuration Summary:${NC}"
    echo -e "  Domain           : ${GREEN}${GITLAB_DOMAIN}${NC}"
    echo -e "  Git SSH Port     : ${GREEN}${GIT_SSH_PORT}${NC}"
    echo -e "  Pangolin IP      : ${GREEN}${PANGOLIN_INTERNAL_IP:-"(all RFC1918)"}${NC}"
    echo -e "  Backup Path      : ${GREEN}${GITLAB_BACKUP_PATH}${NC}"
    echo -e "  Keep Backups     : ${GREEN}${BACKUP_KEEP_DAYS} days${NC}"
    echo -e "  Disable Prom/Graf: ${GREEN}${DISABLE_PROMETHEUS}${NC}"
    echo -e "  Reduce Puma      : ${GREEN}${DISABLE_PUMA_WORKERS}${NC}"
    echo -e "  SMTP             : ${GREEN}${SMTP_ENABLE}${NC}"
    echo ""
    confirm "Proceed with these settings?" "y" || { info "Aborted."; exit 0; }
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 7 — GITLAB.RB GENERATOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

csv_to_ruby_array() {
    local csv="$1" out="["; local -a items
    IFS=',' read -ra items <<< "$csv"
    for item in "${items[@]}"; do item="${item// /}"; out+="'${item}', "; done
    echo "${out%, }]"
}

write_gitlab_rb() {
    [[ ! -f "$GITLAB_RB" ]] && fatal "${GITLAB_RB} not found — is GitLab installed?"
    local bak="/etc/gitlab/gitlab.rb.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$GITLAB_RB" "$bak" && info "Backup saved: ${bak}"
    local trusted_ruby; trusted_ruby=$(csv_to_ruby_array "${TRUSTED_PROXIES}")
    info "Writing /etc/gitlab/gitlab.rb ..."

    cat > "$GITLAB_RB" <<GITLABRB
# =============================================================================
#  /etc/gitlab/gitlab.rb  —  Generated by install-gitlab.sh on $(date)
#  Domain: ${GITLAB_DOMAIN} | Git SSH: ${GIT_SSH_PORT}
# =============================================================================

# External URL — https so GitLab generates correct clone URLs.
# TLS is terminated by Pangolin, NOT GitLab's bundled nginx.
external_url 'https://${GITLAB_DOMAIN}'

# Nginx — listen on plain HTTP (Pangolin → HTTP:80 → GitLab)
nginx['listen_port']  = 80
nginx['listen_https'] = false
nginx['real_ip_trusted_addresses'] = ${trusted_ruby}
nginx['real_ip_header']            = 'X-Forwarded-For'
nginx['real_ip_recursive']         = 'on'
nginx['proxy_set_headers'] = {
  'Host'              => '\$http_host',
  'X-Real-IP'         => '\$remote_addr',
  'X-Forwarded-For'   => '\$proxy_add_x_forwarded_for',
  'X-Forwarded-Proto' => 'https',
  'X-Forwarded-Ssl'   => 'on',
  'X-Forwarded-Port'  => '443',
  'Upgrade'           => '\$http_upgrade',
  'Connection'        => '\$connection_upgrade'
}

# Let's Encrypt — disabled (Pangolin manages TLS certificates)
letsencrypt['enable'] = false

# SSH — advertise correct external host and port in clone URLs
gitlab_rails['gitlab_ssh_host']       = '${GITLAB_DOMAIN}'
gitlab_rails['gitlab_shell_ssh_port'] = ${GIT_SSH_PORT}

# gitlab-sshd — dedicated Git SSH daemon on :${GIT_SSH_PORT}
# System OpenSSH on port 22 is completely untouched.
gitlab_sshd['enable']         = true
gitlab_sshd['listen_address'] = '0.0.0.0:${GIT_SSH_PORT}'

# Backups
gitlab_rails['backup_path']      = '${GITLAB_BACKUP_PATH}'
gitlab_rails['backup_keep_time'] = ${BACKUP_KEEP_TIME}

# SMTP
$(if [[ "${SMTP_ENABLE}" == "true" ]]; then
cat <<SMTP
gitlab_rails['smtp_enable']               = true
gitlab_rails['smtp_address']              = '${SMTP_ADDRESS}'
gitlab_rails['smtp_port']                 = ${SMTP_PORT}
gitlab_rails['smtp_user_name']            = '${SMTP_USER}'
gitlab_rails['smtp_password']             = '${SMTP_PASS}'
gitlab_rails['smtp_domain']               = '${SMTP_DOMAIN}'
gitlab_rails['smtp_authentication']       = 'login'
gitlab_rails['smtp_enable_starttls_auto'] = ${SMTP_TLS}
gitlab_rails['gitlab_email_from']         = '${GITLAB_EMAIL_FROM}'
gitlab_rails['gitlab_email_display_name'] = 'GitLab'
SMTP
else
echo "gitlab_rails['smtp_enable'] = false"
fi)

# Performance
$(if [[ "${DISABLE_PROMETHEUS}" == "true" ]]; then
cat <<PROM
prometheus['enable']            = false
prometheus_monitoring['enable'] = false
grafana['enable']               = false
alertmanager['enable']          = false
node_exporter['enable']         = false
redis_exporter['enable']        = false
postgres_exporter['enable']     = false
pgbouncer_exporter['enable']    = false
gitlab_exporter['enable']       = false
PROM
fi)
$(if [[ "${DISABLE_PUMA_WORKERS}" == "true" ]]; then
cat <<PUMA
puma['worker_processes'] = 2
puma['min_threads']      = 1
puma['max_threads']      = 4
PUMA
fi)

# Misc
gitlab_rails['usage_ping_enabled'] = false
gitlab_rails['time_zone']          = 'UTC'
GITLABRB

    grep -q "external_url" "$GITLAB_RB" \
        || { cp "$bak" "$GITLAB_RB"; fatal "Generated gitlab.rb is invalid. Backup restored: ${bak}"; }
    success "gitlab.rb written and validated."
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 8 — INSTALL STEPS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

install_step_system_prep() {
    step "STEP 1 — System Preparation"
    state_done "system_prep" && { info "Already done — skipping."; return; }
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl ca-certificates tzdata perl ufw apt-transport-https \
        gnupg2 lsb-release net-tools postfix 2>&1 | tee -a "$LOG_FILE"
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mailname string ${GITLAB_DOMAIN}"      | debconf-set-selections
    dpkg-reconfigure -f noninteractive postfix 2>&1 | tee -a "$LOG_FILE" || true
    hostnamectl set-hostname "${GITLAB_DOMAIN}"
    grep -q "${GITLAB_DOMAIN}" /etc/hosts || echo "127.0.1.1  ${GITLAB_DOMAIN}" >> /etc/hosts
    state_mark "system_prep"; success "System preparation done."
}

install_step_add_repo() {
    step "STEP 2 — GitLab CE Repository"
    state_done "repo_added" && { info "Already done — skipping."; return; }
    if [[ -f "/etc/apt/sources.list.d/gitlab_gitlab-ce.list" ]]; then
        warn "Repo already present — refreshing."
        apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
        state_mark "repo_added"; success "Repo already configured."; return
    fi
    info "Downloading GitLab apt repo setup script..."
    curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh \
        -o /tmp/gl-repo.sh || fatal "Failed to download repo script."
    bash /tmp/gl-repo.sh 2>&1 | tee -a "$LOG_FILE"; rm -f /tmp/gl-repo.sh
    [[ -f "/etc/apt/sources.list.d/gitlab_gitlab-ce.list" ]] \
        || fatal "Repo file not created. See ${LOG_FILE}."
    state_mark "repo_added"; success "GitLab CE repository added."
}

install_step_install_package() {
    step "STEP 3 — Install GitLab CE Package"
    case "${INSTALL_ACTION:-fresh}" in
        reconfigure-only) info "Skipping (reconfigure-only)."; state_mark "gitlab_installed"; return ;;
        upgrade)
            state_done "gitlab_installed" && { info "Already done."; return; }
            info "Upgrading gitlab-ce..."
            apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
            DEBIAN_FRONTEND=noninteractive apt-get install -y gitlab-ce 2>&1 | tee -a "$LOG_FILE" \
                || fatal "Upgrade failed. See ${LOG_FILE}."
            state_mark "gitlab_installed"; success "Upgraded to $(gitlab_installed_version)."; return ;;
        verify-only) info "Verify-only — skipping."; state_mark "gitlab_installed"; return ;;
    esac
    state_done "gitlab_installed" && { info "Already done — skipping."; return; }
    info "Installing gitlab-ce (5–10 minutes)..."
    EXTERNAL_URL="http://${GITLAB_DOMAIN}" DEBIAN_FRONTEND=noninteractive \
        apt-get install -y gitlab-ce 2>&1 | tee -a "$LOG_FILE" \
        || {
            error "Install failed — attempting dpkg repair and retry..."
            repair_gitlab dpkg-fix
            EXTERNAL_URL="http://${GITLAB_DOMAIN}" DEBIAN_FRONTEND=noninteractive \
                apt-get install -y gitlab-ce 2>&1 | tee -a "$LOG_FILE" \
                || fatal "Install still failing after repair. See ${LOG_FILE}."
        }
    gitlab_is_installed || fatal "gitlab-ce not in clean state post-install."
    state_mark "gitlab_installed"; success "GitLab CE installed ($(gitlab_installed_version))."
}

install_step_configure() {
    step "STEP 4 — Write gitlab.rb"
    if state_done "gitlab_configured" && [[ "${INSTALL_ACTION:-fresh}" != "reconfigure-only" ]]; then
        info "Already done — skipping."; return
    fi
    write_gitlab_rb
    state_mark "gitlab_configured"
}

install_step_reconfigure() {
    step "STEP 5 — gitlab-ctl reconfigure"
    info "Checking for corrupted secrets file before reconfigure..."
    fix_corrupt_secrets || true
    info "Running gitlab-ctl reconfigure (2–5 minutes)..."
    timeout 600 gitlab-ctl reconfigure 2>&1 | tee -a "$LOG_FILE" \
        || {
            error "Reconfigure failed."
            if [[ "$UNATTENDED" == "true" ]]; then fatal "Reconfigure failed. See ${LOG_FILE}."; fi
            echo -e "  ${YELLOW}Options:${NC}"
            echo -e "    ${CYAN}(r)${NC} Retry  (p) Purge+reinstall  (m) Shell  (q) Quit"
            echo -ne "  Choice: "; read -r ch
            case "${ch,,}" in
                r) timeout 600 gitlab-ctl reconfigure 2>&1 | tee -a "$LOG_FILE" || fatal "Failed again." ;;
                p) repair_gitlab purge-reinstall; timeout 600 gitlab-ctl reconfigure 2>&1 | tee -a "$LOG_FILE" || fatal "Still failing." ;;
                m) open_repair_shell ;;
                *) fatal "Aborted." ;;
            esac
        }
    info "Restarting all services..."; gitlab-ctl restart 2>&1 | tee -a "$LOG_FILE"
    info "Waiting 15s..."; sleep 15
    local failed=()
    for svc in nginx puma gitaly postgresql redis; do
        gitlab-ctl status 2>/dev/null | grep -q "^run: ${svc}" || failed+=("$svc")
    done
    if (( ${#failed[@]} > 0 )); then
        warn "Retrying failed services: ${failed[*]}"
        for svc in "${failed[@]}"; do gitlab-ctl restart "$svc" 2>&1 | tee -a "$LOG_FILE" || true; done
        sleep 8
        local still=()
        for svc in "${failed[@]}"; do
            gitlab-ctl status 2>/dev/null | grep -q "^run: ${svc}" || still+=("$svc")
        done
        (( ${#still[@]} > 0 )) && fatal "Services still down: ${still[*]}. Run: sudo gitlab-ctl tail ${still[0]}"
    fi
    success "All critical services running."
}

install_step_firewall() {
    step "STEP 6 — UFW Firewall"
    state_done "firewall_configured" && { info "Already done — skipping."; return; }
    command -v ufw &>/dev/null || apt-get install -y ufw 2>&1 | tee -a "$LOG_FILE"
    ufw --force reset 2>&1 | tee -a "$LOG_FILE"
    ufw allow 22/tcp            comment "Admin SSH"
    ufw allow 80/tcp            comment "HTTP Pangolin backend"
    ufw allow "${GIT_SSH_PORT}/tcp" comment "Git SSH gitlab-sshd"
    [[ "${ALLOW_DIRECT_HTTPS:-false}" == "true" ]] && ufw allow 443/tcp comment "HTTPS direct"
    if [[ -n "${PANGOLIN_INTERNAL_IP:-}" ]]; then
        ufw delete allow 80/tcp 2>/dev/null || true
        ufw allow from "${PANGOLIN_INTERNAL_IP}" to any port 80 proto tcp comment "HTTP Pangolin IP-restricted"
        info "Port 80 restricted to Pangolin IP: ${PANGOLIN_INTERNAL_IP}"
    fi
    ufw default deny incoming; ufw default allow outgoing
    ufw --force enable 2>&1 | tee -a "$LOG_FILE"
    ufw status verbose | tee -a "$LOG_FILE"
    state_mark "firewall_configured"; success "UFW configured."
}

install_step_backups() {
    step "STEP 7 — Automated Backups"
    state_done "backups_configured" && { info "Already done — skipping."; return; }
    mkdir -p "${GITLAB_BACKUP_PATH}"
    chown git:git "${GITLAB_BACKUP_PATH}" 2>/dev/null || true
    chmod 700 "${GITLAB_BACKUP_PATH}"
    cat > /etc/cron.d/gitlab-backup <<CRON
# GitLab CE daily backup — managed by install-gitlab.sh
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /opt/gitlab/bin/gitlab-backup create CRON=1 2>&1 | logger -t gitlab-backup
CRON
    chmod 644 /etc/cron.d/gitlab-backup
    state_mark "backups_configured"
    success "Daily backup cron set (02:00 AM → ${GITLAB_BACKUP_PATH}, ${BACKUP_KEEP_DAYS}d retention)."
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 9 — HEALTH VERIFICATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

run_verification() {
    step "Health Verification"
    local pass=0 fail=0 wcnt=0
    _vok()  { echo -e "    ${GREEN}✓${NC}  $*"; ((pass++)); }
    _vfail(){ echo -e "    ${RED}✗${NC}  $*"; ((fail++)); }
    _vwarn(){ echo -e "    ${YELLOW}!${NC}  $*"; ((wcnt++)); }

    echo -e "\n  ${BOLD}${CYAN}OS & Hardware${NC}"
    detect_os
    [[ "${OS_ID,,}" == "ubuntu" && "$OS_VERSION" == "22.04" ]] \
        && _vok "Ubuntu 22.04 — fully supported" \
        || _vwarn "OS: ${OS_PRETTY} — not the tested platform"
    check_disk
    case $? in 0|2) _vok "Disk free: ${DISK_FREE_GB} GB" ;; 1) _vfail "Disk free: ${DISK_FREE_GB} GB — critically low" ;; esac
    check_ram
    local avail; avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
    (( avail > 512 )) && _vok "Memory available: ${avail} MB" || _vfail "Memory available: ${avail} MB — too low"
    local swap; swap=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo)
    (( swap > 0 )) && _vok "Swap: ${swap} MB" || _vwarn "No swap configured — recommended if RAM < 8 GB"
    local oom; oom=$(dmesg 2>/dev/null | grep -c "oom_kill.*ruby\|oom_kill.*puma\|oom_kill.*postgres" || echo 0)
    (( oom > 0 )) && _vfail "OOM kills detected (${oom}x) — add more RAM" || _vok "No OOM kills detected"

    echo -e "\n  ${BOLD}${CYAN}Package State${NC}"
    detect_gitlab_health
    case "$GITLAB_HEALTH" in
        healthy)  _vok  "GitLab CE ${GITLAB_INSTALLED_VERSION} installed and healthy" ;;
        degraded) _vwarn "GitLab ${GITLAB_INSTALLED_VERSION} degraded: ${GITLAB_BROKEN_REASON}" ;;
        broken)   _vfail "GitLab ${GITLAB_INSTALLED_VERSION} broken: ${GITLAB_BROKEN_REASON}" ;;
        partial)  _vfail "Partial install: ${GITLAB_BROKEN_REASON}" ;;
        none)     _vfail "GitLab CE not installed" ;;
    esac

    echo -e "\n  ${BOLD}${CYAN}Services${NC}"
    for svc in nginx puma sidekiq gitaly postgresql redis gitlab-sshd; do
        if gitlab-ctl status 2>/dev/null | grep -q "^run: ${svc}"; then
            _vok "${svc} running"
        elif gitlab-ctl status 2>/dev/null | grep -q "${svc}"; then
            _vfail "${svc} is DOWN — sudo gitlab-ctl restart ${svc}"
        else
            _vwarn "${svc} not found (may be disabled)"
        fi
    done

    echo -e "\n  ${BOLD}${CYAN}Ports${NC}"
    ss -tlnp 2>/dev/null | grep -q ':80 '               && _vok  "Port 80 open (nginx)"              || _vfail "Port 80 NOT listening"
    ss -tlnp 2>/dev/null | grep -q ":${GIT_SSH_PORT} "  && _vok  "Port ${GIT_SSH_PORT} open (gitlab-sshd)" || _vfail "Port ${GIT_SSH_PORT} NOT listening"
    ss -tlnp 2>/dev/null | grep -q ':22 '               && _vok  "Port 22 open (system SSH)"         || _vwarn "Port 22 not listening"

    echo -e "\n  ${BOLD}${CYAN}HTTP Response${NC}"
    local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
        -H "Host: ${GITLAB_DOMAIN}" "http://localhost:80" 2>/dev/null || echo "000")
    case "$code" in
        200|301|302) _vok  "HTTP ${code} from localhost:80" ;;
        422)         _vwarn "HTTP 422 — proxy header or CSRF misconfiguration" ;;
        502)         _vfail "HTTP 502 — Puma/Workhorse may be down" ;;
        000)         _vfail "No response on localhost:80 — nginx down?" ;;
        *)           _vwarn "HTTP ${code} — investigate if unexpected" ;;
    esac

    echo -e "\n  ${BOLD}${CYAN}gitlab.rb Config${NC}"
    [[ -f "$GITLAB_RB" ]] && _vok "gitlab.rb exists" || { _vfail "gitlab.rb missing"; }
    if [[ -f "$GITLAB_RB" ]]; then
        grep -qE "listen_https.*false"        "$GITLAB_RB" && _vok  "nginx listen_https = false"         || _vfail "nginx listen_https not false — proxy will break"
        grep -q  "letsencrypt.*false"         "$GITLAB_RB" && _vok  "Let's Encrypt disabled"              || _vwarn "letsencrypt may be enabled — will fail behind Pangolin"
        grep -q  "X-Forwarded-Proto.*https"   "$GITLAB_RB" && _vok  "X-Forwarded-Proto: https"            || _vfail "X-Forwarded-Proto missing — HTTPS detection will fail"
        grep -q  "X-Forwarded-Ssl.*on"        "$GITLAB_RB" && _vok  "X-Forwarded-Ssl: on"                 || _vwarn "X-Forwarded-Ssl not set"
        grep -qE "gitlab_sshd.*enable.*true"  "$GITLAB_RB" && _vok  "gitlab-sshd enabled"                 || _vfail "gitlab-sshd not enabled"
        grep -q  "gitlab_shell_ssh_port.*${GIT_SSH_PORT}" "$GITLAB_RB" \
                                                            && _vok  "SSH port advertised: ${GIT_SSH_PORT}" || _vwarn "SSH port may not match ${GIT_SSH_PORT}"
        grep -q  "backup_keep_time"           "$GITLAB_RB" && _vok  "Backup retention configured"          || _vwarn "backup_keep_time not set"
    fi

    echo -e "\n  ${BOLD}${CYAN}Firewall${NC}"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        _vok "UFW active"
        ufw status | grep -qE "^22(/tcp)?\s+ALLOW"              && _vok  "Port 22 allowed"                || _vfail "Port 22 NOT allowed — risk of SSH lockout!"
        ufw status | grep -qE "^80(/tcp)?\s+ALLOW|Pangolin"     && _vok  "Port 80 allowed"                || _vfail "Port 80 NOT allowed"
        ufw status | grep -qE "^${GIT_SSH_PORT}(/tcp)?\s+ALLOW" && _vok  "Port ${GIT_SSH_PORT} allowed"  || _vfail "Port ${GIT_SSH_PORT} NOT allowed"
    else
        _vwarn "UFW not active"
    fi

    echo -e "\n  ${BOLD}${CYAN}Backups${NC}"
    [[ -d "${GITLAB_BACKUP_PATH:-/var/opt/gitlab/backups}" ]] \
        && _vok "Backup directory exists"  || _vwarn "Backup directory missing"
    [[ -f "/etc/cron.d/gitlab-backup" ]] \
        && _vok "Backup cron installed"    || _vwarn "Backup cron not found"

    echo -e "\n  ${BOLD}${CYAN}Recent Errors${NC}"
    local nge="/var/log/gitlab/nginx/gitlab_error.log"
    [[ -f "$nge" ]] && {
        local ec; ec=$(tail -50 "$nge" 2>/dev/null | grep -c "error" || echo 0)
        (( ec == 0 )) && _vok "nginx: no recent errors" || _vwarn "nginx: ${ec} recent error entries"
    } || _vok "nginx error log not yet created (normal on fresh install)"

    # Result
    echo ""; hr
    echo -e "  ${GREEN}Passed: ${pass}${NC}   ${YELLOW}Warnings: ${wcnt}${NC}   ${RED}Failed: ${fail}${NC}"
    hr; echo ""

    if (( fail > 0 )) && [[ "$UNATTENDED" != "true" ]]; then
        confirm "Attempt auto-repair of failed checks?" "y" && repair_gitlab auto || true
    elif (( fail == 0 && wcnt == 0 )); then
        success "All checks passed — GitLab is healthy!"
    elif (( fail == 0 )); then
        warn "Checks passed with warnings — review above."
    fi

    echo ""
    echo -e "  ${BOLD}Manual Tests${NC}"
    echo -e "    ${CYAN}ssh -T -p ${GIT_SSH_PORT} git@localhost${NC}               # from this VM"
    echo -e "    ${CYAN}ssh -T -p ${GIT_SSH_PORT} git@${GITLAB_DOMAIN}${NC}   # from remote"
    echo -e "    ${DIM}Expected: \"Welcome to GitLab, @root!\"${NC}"
    echo ""
    echo -e "    ${CYAN}curl -I -H 'Host: ${GITLAB_DOMAIN}' http://$(hostname -I | awk '{print $1}'):80${NC}"
    echo -e "    ${DIM}(Test that Pangolin can reach GitLab's HTTP backend)${NC}"
    echo ""
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 10 — FINAL SUMMARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_summary() {
    local pw="(already rotated — check GitLab UI)"
    [[ -f "/etc/gitlab/initial_root_password" ]] && \
        pw=$(awk '/Password:/{print $2}' /etc/gitlab/initial_root_password)

    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                   GitLab CE Installation Complete!                  ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BOLD}Access${NC}"
    echo -e "  Web UI  : ${GREEN}https://${GITLAB_DOMAIN}${NC}"
    echo -e "  Git SSH : ${GREEN}ssh://git@${GITLAB_DOMAIN}:${GIT_SSH_PORT}${NC}"
    echo ""
    echo -e "${BOLD}Initial Root Login${NC}"
    echo -e "  Username : ${GREEN}root${NC}"
    echo -e "  Password : ${GREEN}${pw}${NC}"
    echo -e "  ${RED}Change this password immediately after first login!${NC}"
    echo ""
    echo -e "${BOLD}Pangolin Config${NC}"
    echo -e "  Backend  : ${GREEN}http://$(hostname -I | awk '{print $1}'):80${NC}"
    echo -e "  Headers  : ${GREEN}X-Forwarded-Proto: https${NC}  +  WebSocket: enabled"
    echo ""
    echo -e "${BOLD}Git SSH Exposure${NC}"
    echo -e "  Forward external port ${GIT_SSH_PORT} → ${GREEN}$(hostname -I | awk '{print $1}'):${GIT_SSH_PORT}${NC}"
    echo -e "  (on your Proxmox host NAT or upstream firewall)"
    echo ""
    echo -e "${BOLD}Post-Install Hardening${NC}"
    echo -e "  1. Change root password in GitLab UI"
    echo -e "  2. Admin → Settings → Sign-up restrictions → disable open registration"
    echo -e "  3. Admin → Settings → Sign-in restrictions → enforce 2FA"
    echo ""
    echo -e "${BOLD}Commands${NC}"
    echo -e "  ${CYAN}sudo gitlab-ctl status${NC}"
    echo -e "  ${CYAN}sudo gitlab-ctl tail${NC}"
    echo -e "  ${CYAN}sudo gitlab-ctl reconfigure${NC}"
    echo -e "  ${CYAN}sudo gitlab-backup create${NC}"
    echo -e "  ${CYAN}sudo bash install-gitlab.sh --verify-only${NC}"
    echo ""
    echo -e "${DIM}Log: ${LOG_FILE}${NC}"
    echo ""
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 11 — ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Handle standalone --verify-only flag
for arg in "$@"; do
    if [[ "$arg" == "--verify-only" ]]; then
        [[ $EUID -ne 0 ]] && fatal "Run as root: sudo bash $0 --verify-only"
        detect_os; check_ram; check_disk
        GITLAB_DOMAIN="${GITLAB_DOMAIN:-$(hostname -f)}"
        GIT_SSH_PORT="${GIT_SSH_PORT:-2222}"
        GITLAB_BACKUP_PATH="${GITLAB_BACKUP_PATH:-/var/opt/gitlab/backups}"
        run_verification
        exit 0
    fi
done

main() {
    echo ""
    echo -e "${BOLD}${BLUE}"
    echo "  ╔═══════════════════════════════════════════════════════════════════╗"
    echo "  ║       GitLab CE — Single-File Automated Installer v3.0           ║"
    echo "  ║       Ubuntu 22.04 | Pangolin Proxy | Separate Git SSH           ║"
    echo "  ╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  Log  : ${DIM}${LOG_FILE}${NC}"
    echo -e "  State: ${DIM}${STATE_FILE}${NC}"
    echo -e "  ${DIM}Tip: --fresh to restart all steps, --verify-only for health check${NC}"
    echo ""

    run_preflight

    [[ "${INSTALL_ACTION:-fresh}" == "verify-only" ]] && { run_verification; exit 0; }

    run_config_wizard

    echo ""
    echo -e "  ${BOLD}Plan: ${CYAN}${INSTALL_ACTION}${NC}"
    confirm "Ready to proceed?" "y" || { info "Aborted."; exit 0; }
    echo ""

    install_step_system_prep
    install_step_add_repo
    install_step_install_package
    install_step_configure
    install_step_reconfigure
    install_step_firewall
    install_step_backups

    run_verification
    print_summary
}

main "$@"
