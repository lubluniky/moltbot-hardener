#!/bin/sh
# harden-sandbox.sh - Enable and configure sandbox isolation for Moltbot
# Enables sandbox mode, sets network isolation, drops capabilities, validates mounts

set -e

# -----------------------------------------------------------------------------
# Colors and formatting
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${MOLTBOT_CONFIG_DIR:-$HOME/.clawdbot}"
CONFIG_FILE="$CONFIG_DIR/config.json"
DRY_RUN=0
VERBOSE=0

# Default sandbox settings
SANDBOX_ENABLED=1
NETWORK_ISOLATION=1
DROP_CAPS=1
READONLY_ROOT=1

# Capabilities to drop (Linux-specific)
DROPPED_CAPS="cap_net_admin,cap_sys_admin,cap_sys_ptrace,cap_sys_module,cap_sys_rawio"

# Allowed bind mounts (paths that are permitted)
ALLOWED_MOUNTS="$HOME/.clawdbot:$HOME/.clawdbot/sessions:$HOME/.clawdbot/logs:/tmp"

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
print_header() {
    printf "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}${BLUE}  %s${NC}\n" "$1"
    printf "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}\n\n"
}

print_step() {
    printf "${CYAN}▸${NC} %s\n" "$1"
}

print_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}⚠${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}✗${NC} %s\n" "$1"
}

print_info() {
    printf "${BLUE}ℹ${NC} %s\n" "$1"
}

run_cmd() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} %s\n" "$*"
        return 0
    fi
    if [ "$VERBOSE" -eq 1 ]; then
        printf "${CYAN}[RUN]${NC} %s\n" "$*"
    fi
    "$@"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

detect_os() {
    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            ;;
        Linux*)
            OS="linux"
            ;;
        *)
            OS="unknown"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Configuration helpers
# -----------------------------------------------------------------------------
ensure_config_dir() {
    if [ ! -d "$CONFIG_DIR" ]; then
        run_cmd mkdir -p "$CONFIG_DIR"
    fi
}

update_config() {
    key="$1"
    value="$2"
    is_bool="${3:-false}"

    ensure_config_dir

    if [ ! -f "$CONFIG_FILE" ]; then
        echo '{}' > "$CONFIG_FILE"
    fi

    if check_command jq; then
        tmp=$(mktemp)
        if [ "$is_bool" = "true" ]; then
            jq --arg k "$key" --argjson v "$value" '.[$k] = $v' "$CONFIG_FILE" > "$tmp"
        else
            jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$CONFIG_FILE" > "$tmp"
        fi
        mv "$tmp" "$CONFIG_FILE"
    else
        print_error "jq is required for config updates"
        exit 1
    fi
}

update_nested_config() {
    parent="$1"
    child="$2"
    value="$3"
    is_bool="${4:-false}"

    ensure_config_dir

    if [ ! -f "$CONFIG_FILE" ]; then
        echo '{}' > "$CONFIG_FILE"
    fi

    if check_command jq; then
        tmp=$(mktemp)
        if [ "$is_bool" = "true" ]; then
            jq --arg p "$parent" --arg c "$child" --argjson v "$value" \
                '.[$p] = (.[$p] // {}) | .[$p][$c] = $v' "$CONFIG_FILE" > "$tmp"
        else
            jq --arg p "$parent" --arg c "$child" --arg v "$value" \
                '.[$p] = (.[$p] // {}) | .[$p][$c] = $v' "$CONFIG_FILE" > "$tmp"
        fi
        mv "$tmp" "$CONFIG_FILE"
    else
        print_error "jq is required for config updates"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Sandbox configuration
# -----------------------------------------------------------------------------
enable_sandbox_mode() {
    print_header "Enabling Sandbox Mode"

    print_step "Setting sandbox.enabled = true..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Update config: sandbox.enabled = true\n"
    else
        update_nested_config "sandbox" "enabled" "true" "true"
        print_success "Sandbox mode enabled"
    fi

    print_info "Processes will run in isolated sandbox environment"
}

configure_network_isolation() {
    print_header "Configuring Network Isolation"

    if [ "$NETWORK_ISOLATION" -eq 0 ]; then
        print_info "Network isolation disabled by flag"
        return 0
    fi

    print_step "Setting sandbox.networkIsolation = true..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Update config: sandbox.networkIsolation = true\n"
    else
        update_nested_config "sandbox" "networkIsolation" "true" "true"
        print_success "Network isolation enabled"
    fi

    # Set allowed network endpoints (DNS, localhost)
    print_step "Configuring allowed network endpoints..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Update config: sandbox.allowedEndpoints = [localhost, dns]\n"
    else
        if check_command jq; then
            tmp=$(mktemp)
            jq '.sandbox.allowedEndpoints = ["127.0.0.1", "::1", "localhost"]' "$CONFIG_FILE" > "$tmp"
            mv "$tmp" "$CONFIG_FILE"
        fi
        print_success "Allowed endpoints configured"
    fi

    print_info "Only localhost and DNS traffic will be permitted"
}

drop_capabilities() {
    print_header "Dropping Capabilities"

    if [ "$DROP_CAPS" -eq 0 ]; then
        print_info "Capability dropping disabled by flag"
        return 0
    fi

    if [ "$OS" != "linux" ]; then
        print_info "Capability dropping is Linux-specific, skipping on $OS"
        print_info "macOS uses sandbox-exec for similar isolation"
        return 0
    fi

    print_step "Configuring dropped capabilities..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Update config: sandbox.dropCapabilities = [%s]\n" "$DROPPED_CAPS"
    else
        if check_command jq; then
            caps_json=$(echo "$DROPPED_CAPS" | tr ',' '\n' | jq -R . | jq -s .)
            tmp=$(mktemp)
            jq --argjson caps "$caps_json" '.sandbox.dropCapabilities = $caps' "$CONFIG_FILE" > "$tmp"
            mv "$tmp" "$CONFIG_FILE"
        fi
        print_success "Dangerous capabilities will be dropped"
    fi

    print_info "Dropped: $DROPPED_CAPS"
}

configure_readonly_root() {
    print_header "Configuring Read-Only Root"

    if [ "$READONLY_ROOT" -eq 0 ]; then
        print_info "Read-only root disabled by flag"
        return 0
    fi

    print_step "Setting sandbox.readonlyRoot = true..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Update config: sandbox.readonlyRoot = true\n"
    else
        update_nested_config "sandbox" "readonlyRoot" "true" "true"
        print_success "Read-only root filesystem enabled"
    fi

    print_info "Root filesystem will be mounted read-only"
}

# -----------------------------------------------------------------------------
# Bind mount validation
# -----------------------------------------------------------------------------
validate_bind_mounts() {
    print_header "Validating Bind Mounts"

    print_step "Checking configured bind mounts..."

    local issues_found=0

    # Read current bind mounts from config
    if [ -f "$CONFIG_FILE" ] && check_command jq; then
        mounts=$(jq -r '.sandbox.bindMounts[]? // empty' "$CONFIG_FILE" 2>/dev/null)
    else
        mounts=""
    fi

    # Check each configured mount
    if [ -n "$mounts" ]; then
        echo "$mounts" | while read -r mount; do
            if [ -z "$mount" ]; then
                continue
            fi

            # Extract source path (before the colon if present)
            src_path=$(echo "$mount" | cut -d: -f1)

            # Check if it's an allowed mount
            allowed=0
            IFS=':'
            for allowed_mount in $ALLOWED_MOUNTS; do
                if [ "$src_path" = "$allowed_mount" ]; then
                    allowed=1
                    break
                fi
            done
            unset IFS

            if [ "$allowed" -eq 0 ]; then
                print_warning "Potentially unsafe mount: $mount"
                issues_found=1
            else
                print_success "Allowed mount: $mount"
            fi

            # Check if source exists
            if [ ! -e "$src_path" ] && [ "$DRY_RUN" -eq 0 ]; then
                print_warning "Mount source does not exist: $src_path"
            fi
        done
    else
        print_info "No bind mounts configured"
    fi

    # Configure safe default mounts
    print_step "Setting up safe default bind mounts..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Configure default bind mounts\n"
    else
        if check_command jq; then
            tmp=$(mktemp)
            jq --arg config "$CONFIG_DIR" --arg tmp "/tmp" \
                '.sandbox.bindMounts = [
                    ($config + ":rw"),
                    ($tmp + ":rw")
                ]' "$CONFIG_FILE" > "$tmp"
            mv "$tmp" "$CONFIG_FILE"
        fi
        print_success "Default bind mounts configured"
    fi

    # Validate mount points don't expose sensitive data
    print_step "Checking for sensitive path exposure..."

    sensitive_paths="/etc/passwd /etc/shadow /root /.ssh /etc/ssh $HOME/.ssh $HOME/.gnupg"
    for sens_path in $sensitive_paths; do
        if [ -n "$mounts" ] && echo "$mounts" | grep -qF "$sens_path"; then
            print_error "Sensitive path exposed in bind mounts: $sens_path"
            issues_found=1
        fi
    done

    if [ "$issues_found" -eq 0 ]; then
        print_success "No sensitive paths exposed"
    fi

    return $issues_found
}

# -----------------------------------------------------------------------------
# Docker-specific hardening
# -----------------------------------------------------------------------------
configure_docker_security() {
    print_header "Docker Security Settings"

    if ! check_command docker; then
        print_info "Docker not installed, skipping Docker-specific settings"
        return 0
    fi

    print_step "Configuring Docker security options..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Configure Docker security profile\n"
    else
        if check_command jq; then
            tmp=$(mktemp)
            jq '.sandbox.docker = {
                "securityOpt": ["no-new-privileges:true"],
                "readonlyRootfs": true,
                "capDrop": ["ALL"],
                "capAdd": ["CHOWN", "SETUID", "SETGID"],
                "pidsLimit": 100,
                "memoryLimit": "512m",
                "cpuQuota": 50000
            }' "$CONFIG_FILE" > "$tmp"
            mv "$tmp" "$CONFIG_FILE"
        fi
        print_success "Docker security profile configured"
    fi

    print_info "Containers will run with restricted privileges"
}

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
verify_sandbox_config() {
    print_header "Verifying Sandbox Configuration"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY-RUN] Skipping verification"
        return 0
    fi

    local all_good=1

    if [ -f "$CONFIG_FILE" ] && check_command jq; then
        # Check sandbox enabled
        enabled=$(jq -r '.sandbox.enabled // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$enabled" = "true" ]; then
            print_success "Sandbox enabled: $enabled"
        else
            print_warning "Sandbox enabled: $enabled"
            all_good=0
        fi

        # Check network isolation
        net_iso=$(jq -r '.sandbox.networkIsolation // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$net_iso" = "true" ]; then
            print_success "Network isolation: $net_iso"
        else
            print_warning "Network isolation: $net_iso"
            all_good=0
        fi

        # Check read-only root
        ro_root=$(jq -r '.sandbox.readonlyRoot // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$ro_root" = "true" ]; then
            print_success "Read-only root: $ro_root"
        else
            print_warning "Read-only root: $ro_root"
            all_good=0
        fi

        # Check dropped capabilities
        caps=$(jq -r '.sandbox.dropCapabilities | length // 0' "$CONFIG_FILE" 2>/dev/null)
        if [ "$caps" -gt 0 ]; then
            print_success "Dropped capabilities: $caps configured"
        else
            if [ "$OS" = "linux" ]; then
                print_warning "No capabilities configured to drop"
                all_good=0
            else
                print_info "Capability dropping N/A on $OS"
            fi
        fi
    else
        print_error "Cannot read config file or jq not available"
        all_good=0
    fi

    if [ "$all_good" -eq 1 ]; then
        printf "\n${GREEN}${BOLD}All sandbox hardening checks passed!${NC}\n"
    else
        printf "\n${YELLOW}${BOLD}Some settings need attention.${NC}\n"
    fi
}

# -----------------------------------------------------------------------------
# Usage and main
# -----------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Description:${NC}
    Configures sandbox isolation for Moltbot:
    - Enables sandbox mode
    - Configures network isolation
    - Drops dangerous capabilities (Linux)
    - Validates bind mount security

${BOLD}Options:${NC}
    -h, --help              Show this help message
    -n, --dry-run           Show what would be done without making changes
    -v, --verbose           Enable verbose output
    --no-network            Disable network isolation
    --no-caps               Don't drop capabilities
    --no-readonly           Don't enable read-only root

${BOLD}Examples:${NC}
    $0                      # Full sandbox hardening
    $0 --dry-run            # Preview changes
    $0 --no-network         # Skip network isolation

EOF
}

main() {
    detect_os

    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -n|--dry-run)
                DRY_RUN=1
                ;;
            -v|--verbose)
                VERBOSE=1
                ;;
            --no-network)
                NETWORK_ISOLATION=0
                ;;
            --no-caps)
                DROP_CAPS=0
                ;;
            --no-readonly)
                READONLY_ROOT=0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    print_header "Sandbox Hardening"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_warning "Running in dry-run mode - no changes will be made"
        printf "\n"
    fi

    print_info "Operating System: $OS"
    printf "\n"

    enable_sandbox_mode
    configure_network_isolation
    drop_capabilities
    configure_readonly_root
    validate_bind_mounts
    configure_docker_security
    verify_sandbox_config

    print_header "Sandbox Hardening Complete"
    printf "${GREEN}${BOLD}Sandbox has been hardened successfully!${NC}\n\n"
}

main "$@"
