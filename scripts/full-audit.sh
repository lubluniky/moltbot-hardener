#!/bin/sh
# full-audit.sh - Run all security checks and generate a comprehensive report
# Executes all hardening checks and produces a colored summary

set -e

# -----------------------------------------------------------------------------
# Colors and formatting
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Status indicators
PASS="${GREEN}PASS${NC}"
WARN="${YELLOW}WARN${NC}"
FAIL="${RED}FAIL${NC}"
SKIP="${DIM}SKIP${NC}"

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${MOLTBOT_CONFIG_DIR:-$HOME/.clawdbot}"
CONFIG_FILE="$CONFIG_DIR/config.json"
REPORT_DIR="${REPORT_DIR:-$CONFIG_DIR/reports}"
DRY_RUN=0
VERBOSE=0
JSON_OUTPUT=0

# Audit results
TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNED_CHECKS=0
FAILED_CHECKS=0
SKIPPED_CHECKS=0

# Report storage
REPORT_ITEMS=""

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
print_banner() {
    printf "\n"
    printf "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}${BLUE}║${NC}${BOLD}        MOLTBOT HARDENER - FULL SECURITY AUDIT              ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

print_header() {
    printf "\n${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}\n"
    printf "${BOLD}${CYAN}│${NC} %-62s ${BOLD}${CYAN}│${NC}\n" "$1"
    printf "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────┘${NC}\n\n"
}

print_section() {
    printf "\n${BOLD}${MAGENTA}▸ %s${NC}\n" "$1"
    printf "${DIM}────────────────────────────────────────${NC}\n"
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

# Record a check result
record_check() {
    category="$1"
    check_name="$2"
    status="$3"  # pass, warn, fail, skip
    message="$4"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$status" in
        pass)
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            indicator="$PASS"
            ;;
        warn)
            WARNED_CHECKS=$((WARNED_CHECKS + 1))
            indicator="$WARN"
            ;;
        fail)
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            indicator="$FAIL"
            ;;
        skip)
            SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
            indicator="$SKIP"
            ;;
    esac

    printf "  [%b] %-40s %s\n" "$indicator" "$check_name" "${message:-}"

    # Store for report
    REPORT_ITEMS="$REPORT_ITEMS\n$category|$check_name|$status|$message"
}

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
audit_dependencies() {
    print_header "Dependency Audit"

    print_section "Required Tools"

    # Check for required tools
    for tool in go docker jq openssl curl; do
        if check_command "$tool"; then
            version=$("$tool" --version 2>/dev/null | head -n1 | cut -c1-40 || echo "installed")
            record_check "deps" "$tool" "pass" "$version"
        else
            record_check "deps" "$tool" "warn" "Not installed"
        fi
    done

    print_section "Optional Tools"

    for tool in moltbot dialog whiptail ss netstat; do
        if check_command "$tool"; then
            record_check "deps" "$tool" "pass" "Available"
        else
            record_check "deps" "$tool" "skip" "Not required"
        fi
    done
}

# -----------------------------------------------------------------------------
# Gateway security audit
# -----------------------------------------------------------------------------
audit_gateway() {
    print_header "Gateway Security Audit"

    print_section "Configuration"

    if [ -f "$CONFIG_FILE" ] && check_command jq; then
        # Check gateway.bind
        bind_value=$(jq -r '.gateway.bind // empty' "$CONFIG_FILE" 2>/dev/null)
        if [ "$bind_value" = "loopback" ]; then
            record_check "gateway" "Loopback binding" "pass" "gateway.bind=loopback"
        elif [ -n "$bind_value" ]; then
            record_check "gateway" "Loopback binding" "warn" "gateway.bind=$bind_value"
        else
            record_check "gateway" "Loopback binding" "warn" "Not configured"
        fi

        # Check auth token
        token_value=$(jq -r '.gateway.authToken // empty' "$CONFIG_FILE" 2>/dev/null)
        if [ -n "$token_value" ]; then
            token_len=${#token_value}
            if [ "$token_len" -ge 32 ]; then
                record_check "gateway" "Auth token" "pass" "Configured (${token_len} chars)"
            else
                record_check "gateway" "Auth token" "warn" "Weak token (${token_len} chars)"
            fi
        else
            record_check "gateway" "Auth token" "fail" "Not configured"
        fi

        # Check TLS
        tls_enabled=$(jq -r '.gateway.tls.enabled // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$tls_enabled" = "true" ]; then
            record_check "gateway" "TLS enabled" "pass" "Encrypted"
        else
            record_check "gateway" "TLS enabled" "warn" "Not enabled"
        fi
    else
        record_check "gateway" "Configuration" "skip" "Config file not found"
    fi

    print_section "Network"

    # Check if gateway is running and on what interface
    if pgrep -f "moltbot.*gateway" >/dev/null 2>&1; then
        record_check "gateway" "Gateway running" "pass" "Active"

        # Check listening interface
        if check_command ss; then
            listen_addr=$(ss -ltnp 2>/dev/null | grep -E "18789" | awk '{print $4}' | head -1)
        elif check_command netstat; then
            listen_addr=$(netstat -an 2>/dev/null | grep -E "LISTEN.*18789" | awk '{print $4}' | head -1)
        else
            listen_addr=""
        fi

        if echo "$listen_addr" | grep -qE "127\.0\.0\.1|localhost|\[::1\]"; then
            record_check "gateway" "Listen interface" "pass" "$listen_addr"
        elif [ -n "$listen_addr" ]; then
            record_check "gateway" "Listen interface" "warn" "$listen_addr (not loopback)"
        fi
    else
        record_check "gateway" "Gateway running" "skip" "Not running"
    fi
}

# -----------------------------------------------------------------------------
# Sandbox security audit
# -----------------------------------------------------------------------------
audit_sandbox() {
    print_header "Sandbox Security Audit"

    print_section "Sandbox Configuration"

    if [ -f "$CONFIG_FILE" ] && check_command jq; then
        # Check sandbox enabled
        sandbox_enabled=$(jq -r '.sandbox.enabled // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$sandbox_enabled" = "true" ]; then
            record_check "sandbox" "Sandbox mode" "pass" "Enabled"
        else
            record_check "sandbox" "Sandbox mode" "fail" "Disabled"
        fi

        # Check network isolation
        net_iso=$(jq -r '.sandbox.networkIsolation // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$net_iso" = "true" ]; then
            record_check "sandbox" "Network isolation" "pass" "Enabled"
        else
            record_check "sandbox" "Network isolation" "warn" "Disabled"
        fi

        # Check read-only root
        ro_root=$(jq -r '.sandbox.readonlyRoot // false' "$CONFIG_FILE" 2>/dev/null)
        if [ "$ro_root" = "true" ]; then
            record_check "sandbox" "Read-only root" "pass" "Enabled"
        else
            record_check "sandbox" "Read-only root" "warn" "Disabled"
        fi

        # Check capability dropping (Linux only)
        if [ "$OS" = "linux" ]; then
            caps=$(jq -r '.sandbox.dropCapabilities | length // 0' "$CONFIG_FILE" 2>/dev/null)
            if [ "$caps" -gt 0 ]; then
                record_check "sandbox" "Dropped capabilities" "pass" "$caps configured"
            else
                record_check "sandbox" "Dropped capabilities" "warn" "None configured"
            fi
        else
            record_check "sandbox" "Dropped capabilities" "skip" "N/A on $OS"
        fi
    else
        record_check "sandbox" "Configuration" "skip" "Config not found"
    fi

    print_section "Docker Security"

    if check_command docker; then
        # Check Docker daemon
        if docker info >/dev/null 2>&1; then
            record_check "sandbox" "Docker daemon" "pass" "Running"

            # Check for running containers
            container_count=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
            record_check "sandbox" "Running containers" "pass" "$container_count active"

            # Check for privileged containers
            priv_containers=$(docker ps --format '{{.Names}}' --filter "status=running" 2>/dev/null | while read name; do
                if docker inspect "$name" 2>/dev/null | jq -r '.[0].HostConfig.Privileged' | grep -q "true"; then
                    echo "$name"
                fi
            done)

            if [ -n "$priv_containers" ]; then
                record_check "sandbox" "Privileged containers" "fail" "Found: $priv_containers"
            else
                record_check "sandbox" "Privileged containers" "pass" "None running"
            fi
        else
            record_check "sandbox" "Docker daemon" "warn" "Not running or no access"
        fi
    else
        record_check "sandbox" "Docker" "skip" "Not installed"
    fi
}

# -----------------------------------------------------------------------------
# Credential security audit
# -----------------------------------------------------------------------------
audit_credentials() {
    print_header "Credential Security Audit"

    print_section "File Permissions"

    # Check config directory permissions
    if [ -d "$CONFIG_DIR" ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            mode=$(stat -f "%Lp" "$CONFIG_DIR" 2>/dev/null)
        else
            mode=$(stat -c "%a" "$CONFIG_DIR" 2>/dev/null)
        fi

        if [ "$mode" = "700" ]; then
            record_check "creds" "Config directory" "pass" "mode $mode"
        else
            record_check "creds" "Config directory" "warn" "mode $mode (should be 700)"
        fi
    else
        record_check "creds" "Config directory" "skip" "Does not exist"
    fi

    # Check credentials directory
    creds_dir="$CONFIG_DIR/credentials"
    if [ -d "$creds_dir" ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            mode=$(stat -f "%Lp" "$creds_dir" 2>/dev/null)
        else
            mode=$(stat -c "%a" "$creds_dir" 2>/dev/null)
        fi

        if [ "$mode" = "700" ]; then
            record_check "creds" "Credentials directory" "pass" "mode $mode"
        else
            record_check "creds" "Credentials directory" "warn" "mode $mode"
        fi

        # Count credential files
        cred_count=$(find "$creds_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
        record_check "creds" "Credential files" "pass" "$cred_count stored"
    else
        record_check "creds" "Credentials directory" "skip" "Does not exist"
    fi

    print_section "Secret Exposure"

    # Check for plaintext secrets in common files
    secret_files=0
    for file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.env"; do
        if [ -f "$file" ]; then
            if grep -qiE "(password|secret|token|api.?key).*=" "$file" 2>/dev/null; then
                secret_files=$((secret_files + 1))
            fi
        fi
    done

    if [ "$secret_files" -gt 0 ]; then
        record_check "creds" "Plaintext secrets" "warn" "Found in $secret_files files"
    else
        record_check "creds" "Plaintext secrets" "pass" "None detected"
    fi

    # Check for cloud sync exposure
    print_section "Cloud Sync Exposure"

    sync_exposure=0
    for folder in "Dropbox" "Google Drive" "OneDrive" "iCloud Drive"; do
        sync_path="$HOME/$folder"
        if [ -d "$sync_path" ]; then
            case "$CONFIG_DIR" in
                "$sync_path"*)
                    record_check "creds" "$folder exposure" "fail" "Config in sync folder"
                    sync_exposure=1
                    ;;
                *)
                    record_check "creds" "$folder" "pass" "Config not synced"
                    ;;
            esac
        fi
    done

    if [ "$sync_exposure" -eq 0 ]; then
        record_check "creds" "Cloud sync" "pass" "No exposure detected"
    fi
}

# -----------------------------------------------------------------------------
# System security audit
# -----------------------------------------------------------------------------
audit_system() {
    print_header "System Security Audit"

    print_section "Operating System"

    record_check "system" "OS Type" "pass" "$(uname -s) $(uname -r)"

    # Check for security updates (basic check)
    if [ "$OS" = "macos" ]; then
        if softwareupdate -l 2>&1 | grep -q "No new software available"; then
            record_check "system" "System updates" "pass" "Up to date"
        else
            record_check "system" "System updates" "warn" "Updates available"
        fi
    elif [ "$OS" = "linux" ]; then
        if check_command apt; then
            updates=$(apt list --upgradable 2>/dev/null | wc -l)
            if [ "$updates" -le 1 ]; then
                record_check "system" "System updates" "pass" "Up to date"
            else
                record_check "system" "System updates" "warn" "$updates updates available"
            fi
        else
            record_check "system" "System updates" "skip" "Cannot check"
        fi
    fi

    print_section "Network Security"

    # Check for open ports
    if check_command ss; then
        open_ports=$(ss -ltnp 2>/dev/null | grep -c LISTEN || echo "0")
        record_check "system" "Listening ports" "pass" "$open_ports services"
    elif check_command netstat; then
        open_ports=$(netstat -an 2>/dev/null | grep -c LISTEN || echo "0")
        record_check "system" "Listening ports" "pass" "$open_ports services"
    fi

    # Check firewall status
    if [ "$OS" = "macos" ]; then
        if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled"; then
            record_check "system" "Firewall" "pass" "Enabled"
        else
            record_check "system" "Firewall" "warn" "Disabled"
        fi
    elif [ "$OS" = "linux" ]; then
        if check_command ufw; then
            if ufw status 2>/dev/null | grep -q "active"; then
                record_check "system" "Firewall (ufw)" "pass" "Active"
            else
                record_check "system" "Firewall (ufw)" "warn" "Inactive"
            fi
        elif check_command firewall-cmd; then
            if firewall-cmd --state 2>/dev/null | grep -q "running"; then
                record_check "system" "Firewall (firewalld)" "pass" "Active"
            else
                record_check "system" "Firewall (firewalld)" "warn" "Inactive"
            fi
        else
            record_check "system" "Firewall" "skip" "No firewall tool found"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Generate report
# -----------------------------------------------------------------------------
generate_report() {
    print_header "Audit Summary"

    # Calculate percentages
    if [ "$TOTAL_CHECKS" -gt 0 ]; then
        pass_pct=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
    else
        pass_pct=0
    fi

    # Print summary bar
    printf "\n"
    printf "  ${BOLD}Total Checks:${NC}  %d\n" "$TOTAL_CHECKS"
    printf "  ${GREEN}Passed:${NC}        %d (%d%%)\n" "$PASSED_CHECKS" "$pass_pct"
    printf "  ${YELLOW}Warnings:${NC}      %d\n" "$WARNED_CHECKS"
    printf "  ${RED}Failed:${NC}        %d\n" "$FAILED_CHECKS"
    printf "  ${DIM}Skipped:${NC}       %d\n" "$SKIPPED_CHECKS"

    # Visual progress bar
    printf "\n  ["
    filled=$((pass_pct / 5))
    i=0
    while [ $i -lt 20 ]; do
        if [ $i -lt $filled ]; then
            printf "${GREEN}█${NC}"
        else
            printf "${DIM}░${NC}"
        fi
        i=$((i + 1))
    done
    printf "] %d%%\n" "$pass_pct"

    # Overall status
    printf "\n"
    if [ "$FAILED_CHECKS" -eq 0 ] && [ "$WARNED_CHECKS" -eq 0 ]; then
        printf "  ${GREEN}${BOLD}✓ SECURITY STATUS: EXCELLENT${NC}\n"
        printf "  All checks passed. Your Moltbot installation is well-secured.\n"
    elif [ "$FAILED_CHECKS" -eq 0 ]; then
        printf "  ${YELLOW}${BOLD}⚠ SECURITY STATUS: GOOD${NC}\n"
        printf "  No critical issues, but some improvements recommended.\n"
    else
        printf "  ${RED}${BOLD}✗ SECURITY STATUS: NEEDS ATTENTION${NC}\n"
        printf "  Critical security issues found. Review failed checks above.\n"
    fi

    # Save report to file
    if [ "$DRY_RUN" -eq 0 ]; then
        mkdir -p "$REPORT_DIR"
        report_file="$REPORT_DIR/audit_$(date +%Y%m%d_%H%M%S).txt"

        {
            echo "MOLTBOT HARDENER - SECURITY AUDIT REPORT"
            echo "Generated: $(date)"
            echo "=========================================="
            echo ""
            echo "Summary:"
            echo "  Total Checks:  $TOTAL_CHECKS"
            echo "  Passed:        $PASSED_CHECKS"
            echo "  Warnings:      $WARNED_CHECKS"
            echo "  Failed:        $FAILED_CHECKS"
            echo "  Skipped:       $SKIPPED_CHECKS"
            echo ""
            echo "Details:"
            printf "%b" "$REPORT_ITEMS" | while IFS='|' read -r cat name status msg; do
                if [ -n "$cat" ]; then
                    echo "  [$status] $cat/$name: $msg"
                fi
            done
        } > "$report_file"

        printf "\n  ${BLUE}Report saved:${NC} %s\n" "$report_file"
    fi

    # Recommendations
    if [ "$FAILED_CHECKS" -gt 0 ] || [ "$WARNED_CHECKS" -gt 0 ]; then
        printf "\n${BOLD}${CYAN}Recommended Actions:${NC}\n"

        if echo "$REPORT_ITEMS" | grep -q "gateway.*fail\|gateway.*warn"; then
            printf "  ${CYAN}→${NC} Run: ./scripts/harden-gateway.sh\n"
        fi

        if echo "$REPORT_ITEMS" | grep -q "sandbox.*fail\|sandbox.*warn"; then
            printf "  ${CYAN}→${NC} Run: ./scripts/harden-sandbox.sh\n"
        fi

        if echo "$REPORT_ITEMS" | grep -q "creds.*fail\|creds.*warn"; then
            printf "  ${CYAN}→${NC} Run: ./scripts/secure-credentials.sh\n"
        fi
    fi

    printf "\n"
}

# -----------------------------------------------------------------------------
# Usage and main
# -----------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Description:${NC}
    Runs a comprehensive security audit of your Moltbot installation:
    - Dependency verification
    - Gateway security configuration
    - Sandbox isolation settings
    - Credential file security
    - System security posture

${BOLD}Options:${NC}
    -h, --help          Show this help message
    -n, --dry-run       Don't save report to file
    -v, --verbose       Enable verbose output
    -j, --json          Output results as JSON
    --report-dir DIR    Directory for reports (default: ~/.clawdbot/reports)

${BOLD}Examples:${NC}
    $0                  # Run full audit
    $0 --verbose        # Detailed output
    $0 --json           # JSON output for automation

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
            -j|--json)
                JSON_OUTPUT=1
                ;;
            --report-dir)
                shift
                REPORT_DIR="$1"
                ;;
            *)
                printf "${RED}Unknown option: %s${NC}\n" "$1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    print_banner

    printf "${DIM}Audit started: %s${NC}\n" "$(date)"
    printf "${DIM}Config directory: %s${NC}\n" "$CONFIG_DIR"

    audit_dependencies
    audit_gateway
    audit_sandbox
    audit_credentials
    audit_system
    generate_report
}

main "$@"
