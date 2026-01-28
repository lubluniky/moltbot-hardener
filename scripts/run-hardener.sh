#!/bin/sh
# run-hardener.sh - Main entry point with interactive menu
# Provides an interactive interface to run hardening steps

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

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DRY_RUN=0
VERBOSE=0
NON_INTERACTIVE=0
SELECTED_ACTIONS=""

# Spinner characters
SPINNER_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
print_banner() {
    clear 2>/dev/null || true
    printf "\n"
    printf "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}${BLUE}║${NC}                                                                ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}   ${BOLD}${CYAN}███╗   ███╗${NC} ${BOLD}${GREEN}██████╗${NC}  ${BOLD}${YELLOW}██╗  ████████╗${NC} ${BOLD}${MAGENTA}██████╗${NC}  ${BOLD}${RED}████████╗${NC}   ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}   ${BOLD}${CYAN}████╗ ████║${NC} ${BOLD}${GREEN}██╔═══██╗${NC}${BOLD}${YELLOW}██║  ╚══██╔══╝${NC} ${BOLD}${MAGENTA}██╔══██╗${NC} ${BOLD}${RED}╚══██╔══╝${NC}   ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}   ${BOLD}${CYAN}██╔████╔██║${NC} ${BOLD}${GREEN}██║   ██║${NC}${BOLD}${YELLOW}██║     ██║${NC}    ${BOLD}${MAGENTA}██████╔╝${NC}    ${BOLD}${RED}██║${NC}      ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}   ${BOLD}${CYAN}██║╚██╔╝██║${NC} ${BOLD}${GREEN}██║   ██║${NC}${BOLD}${YELLOW}██║     ██║${NC}    ${BOLD}${MAGENTA}██╔══██╗${NC}    ${BOLD}${RED}██║${NC}      ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}   ${BOLD}${CYAN}██║ ╚═╝ ██║${NC} ${BOLD}${GREEN}╚██████╔╝${NC}${BOLD}${YELLOW}███████╗██║${NC}    ${BOLD}${MAGENTA}██████╔╝${NC}    ${BOLD}${RED}██║${NC}      ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}   ${BOLD}${CYAN}╚═╝     ╚═╝${NC}  ${BOLD}${GREEN}╚═════╝${NC} ${BOLD}${YELLOW}╚══════╝╚═╝${NC}    ${BOLD}${MAGENTA}╚═════╝${NC}     ${BOLD}${RED}╚═╝${NC}      ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}                                                                ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}           ${BOLD}${GREEN}H A R D E N E R${NC}   ${DIM}Security Toolkit${NC}                  ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}║${NC}                                                                ${BOLD}${BLUE}║${NC}\n"
    printf "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

print_header() {
    printf "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}${BLUE}  %s${NC}\n" "$1"
    printf "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}\n\n"
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

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# Bot status check - CRITICAL for safe operation
# -----------------------------------------------------------------------------
check_moltbot_running() {
    # First try official moltbot gateway status command
    if command -v moltbot >/dev/null 2>&1; then
        # moltbot gateway status returns 0 if running, non-zero otherwise
        if moltbot gateway status --no-probe >/dev/null 2>&1; then
            # Check if status indicates running
            local status_output
            status_output=$(moltbot gateway status --no-probe 2>/dev/null)
            if echo "$status_output" | grep -qi "running\|active"; then
                return 0  # Running
            fi
        fi
    fi

    # Fallback: Check for moltbot gateway process directly
    if pgrep -f "moltbot-gateway\|moltbot gateway" >/dev/null 2>&1; then
        return 0  # Running
    fi

    # Check for Moltbot.app on macOS
    if [ "$(uname)" = "Darwin" ]; then
        if pgrep -f "Moltbot.app" >/dev/null 2>&1; then
            return 0  # Running
        fi
        # Check launchd service
        if launchctl print "gui/$(id -u)/bot.molt.gateway" >/dev/null 2>&1; then
            return 0  # Running via launchd
        fi
    fi

    return 1  # Not running
}

warn_if_bot_running() {
    if check_moltbot_running; then
        printf "\n"
        printf "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}\n"
        printf "${RED}║${NC} ${BOLD}${YELLOW}⚠️  WARNING: MOLTBOT IS CURRENTLY RUNNING${NC}                          ${RED}║${NC}\n"
        printf "${RED}╠══════════════════════════════════════════════════════════════════╣${NC}\n"
        printf "${RED}║${NC}                                                                  ${RED}║${NC}\n"
        printf "${RED}║${NC}  ${BOLD}Applying fixes while bot is running is NOT recommended.${NC}        ${RED}║${NC}\n"
        printf "${RED}║${NC}                                                                  ${RED}║${NC}\n"
        printf "${RED}║${NC}  Problems you may encounter:                                     ${RED}║${NC}\n"
        printf "${RED}║${NC}    • Gateway changes won't take effect until restart             ${RED}║${NC}\n"
        printf "${RED}║${NC}    • Sandbox settings won't apply to running agents              ${RED}║${NC}\n"
        printf "${RED}║${NC}    • Config files may be locked or overwritten                   ${RED}║${NC}\n"
        printf "${RED}║${NC}    • Race conditions may corrupt configuration                   ${RED}║${NC}\n"
        printf "${RED}║${NC}                                                                  ${RED}║${NC}\n"
        printf "${RED}║${NC}  ${BOLD}${GREEN}Recommended:${NC}                                                     ${RED}║${NC}\n"
        printf "${RED}║${NC}    1. Stop gateway:  ${CYAN}moltbot gateway stop${NC}                        ${RED}║${NC}\n"
        printf "${RED}║${NC}    2. Run hardener:  ${CYAN}./hardener apply${NC}                            ${RED}║${NC}\n"
        printf "${RED}║${NC}    3. Start gateway: ${CYAN}moltbot gateway start${NC}                       ${RED}║${NC}\n"
        printf "${RED}║${NC}                                                                  ${RED}║${NC}\n"
        printf "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}\n"
        printf "\n"

        if [ "$NON_INTERACTIVE" -eq 0 ]; then
            printf "${YELLOW}Do you want to continue anyway? [y/N]:${NC} "
            read -r response
            case "$response" in
                [yY]|[yY][eE][sS])
                    print_warning "Continuing with bot running - some fixes may not take effect"
                    return 0
                    ;;
                *)
                    print_info "Aborted. Stop moltbot and run again."
                    exit 0
                    ;;
            esac
        else
            print_error "Bot is running. Use --force to continue anyway, or stop the bot first."
            exit 1
        fi
    else
        print_success "Moltbot is not running - safe to apply fixes"
    fi
}

# Check if this is audit-only mode (safe even when running)
is_audit_only() {
    case "$1" in
        audit|scan|check|list|help|version)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Spinner function for long-running tasks
spinner() {
    local pid=$1
    local message="$2"
    local i=0
    local sp_len=${#SPINNER_CHARS}

    # Hide cursor
    printf "\033[?25l"

    while kill -0 "$pid" 2>/dev/null; do
        i=$(((i + 1) % sp_len))
        char=$(printf '%s' "$SPINNER_CHARS" | cut -c$((i + 1)))
        printf "\r${CYAN}%s${NC} %s" "$char" "$message"
        sleep 0.1
    done

    # Show cursor and clear line
    printf "\033[?25h"
    printf "\r\033[K"
}

run_with_spinner() {
    local message="$1"
    shift

    if [ -t 1 ] && [ "$NON_INTERACTIVE" -eq 0 ]; then
        # Run command in background and show spinner
        ("$@") &
        local pid=$!
        spinner $pid "$message"
        wait $pid
        local result=$?

        if [ $result -eq 0 ]; then
            print_success "$message"
        else
            print_error "$message - failed"
        fi
        return $result
    else
        # Non-interactive mode
        printf "%s... " "$message"
        if "$@"; then
            printf "${GREEN}done${NC}\n"
            return 0
        else
            printf "${RED}failed${NC}\n"
            return 1
        fi
    fi
}

# -----------------------------------------------------------------------------
# Dependency checking
# -----------------------------------------------------------------------------
check_dependencies() {
    print_header "Checking Dependencies"

    local missing=""
    local all_ok=1

    # Check required tools
    for tool in jq openssl; do
        if check_command "$tool"; then
            print_success "$tool installed"
        else
            print_warning "$tool not found"
            missing="$missing $tool"
            all_ok=0
        fi
    done

    # Check optional tools
    for tool in docker go moltbot; do
        if check_command "$tool"; then
            print_success "$tool installed"
        else
            print_info "$tool not found (optional)"
        fi
    done

    # Check for dialog/whiptail
    if check_command dialog; then
        MENU_TOOL="dialog"
        print_success "dialog available for menus"
    elif check_command whiptail; then
        MENU_TOOL="whiptail"
        print_success "whiptail available for menus"
    else
        MENU_TOOL="native"
        print_info "Using native shell menus"
    fi

    if [ -n "$missing" ]; then
        printf "\n"
        print_warning "Missing dependencies:$missing"
        print_info "Install with: brew install$missing (macOS)"
        print_info "           or: apt install$missing (Linux)"
    fi

    return 0
}

# -----------------------------------------------------------------------------
# Menu functions
# -----------------------------------------------------------------------------
show_native_menu() {
    printf "\n${BOLD}${CYAN}Select an action:${NC}\n\n"
    printf "  ${CYAN}1)${NC} ${BOLD}Full Audit${NC}         - Run comprehensive security audit\n"
    printf "  ${CYAN}2)${NC} ${BOLD}Harden Gateway${NC}     - Secure gateway configuration\n"
    printf "  ${CYAN}3)${NC} ${BOLD}Harden Sandbox${NC}     - Enable sandbox isolation\n"
    printf "  ${CYAN}4)${NC} ${BOLD}Secure Credentials${NC} - Fix permissions, detect secrets\n"
    printf "  ${CYAN}5)${NC} ${BOLD}Install Hardener${NC}   - Install moltbot-hardener binary\n"
    printf "  ${CYAN}6)${NC} ${BOLD}Run All${NC}            - Run all hardening steps\n"
    printf "  ${CYAN}q)${NC} ${BOLD}Quit${NC}\n"
    printf "\n"
    printf "${CYAN}Enter choice [1-6,q]:${NC} "

    read -r choice

    case "$choice" in
        1) SELECTED_ACTIONS="audit" ;;
        2) SELECTED_ACTIONS="gateway" ;;
        3) SELECTED_ACTIONS="sandbox" ;;
        4) SELECTED_ACTIONS="credentials" ;;
        5) SELECTED_ACTIONS="install" ;;
        6) SELECTED_ACTIONS="all" ;;
        q|Q) exit 0 ;;
        *)
            print_warning "Invalid choice"
            return 1
            ;;
    esac
    return 0
}

show_dialog_menu() {
    choice=$(dialog --clear --backtitle "Moltbot Hardener" \
        --title "Security Hardening Menu" \
        --menu "Select an action:" 20 60 7 \
        1 "Full Audit - Run comprehensive security audit" \
        2 "Harden Gateway - Secure gateway configuration" \
        3 "Harden Sandbox - Enable sandbox isolation" \
        4 "Secure Credentials - Fix permissions, detect secrets" \
        5 "Install Hardener - Install moltbot-hardener binary" \
        6 "Run All - Run all hardening steps" \
        q "Quit" \
        2>&1 >/dev/tty)

    clear

    case "$choice" in
        1) SELECTED_ACTIONS="audit" ;;
        2) SELECTED_ACTIONS="gateway" ;;
        3) SELECTED_ACTIONS="sandbox" ;;
        4) SELECTED_ACTIONS="credentials" ;;
        5) SELECTED_ACTIONS="install" ;;
        6) SELECTED_ACTIONS="all" ;;
        q|"") exit 0 ;;
    esac
}

show_whiptail_menu() {
    choice=$(whiptail --clear --backtitle "Moltbot Hardener" \
        --title "Security Hardening Menu" \
        --menu "Select an action:" 20 60 7 \
        1 "Full Audit - Run comprehensive security audit" \
        2 "Harden Gateway - Secure gateway configuration" \
        3 "Harden Sandbox - Enable sandbox isolation" \
        4 "Secure Credentials - Fix permissions, detect secrets" \
        5 "Install Hardener - Install moltbot-hardener binary" \
        6 "Run All - Run all hardening steps" \
        q "Quit" \
        3>&1 1>&2 2>&3)

    clear

    case "$choice" in
        1) SELECTED_ACTIONS="audit" ;;
        2) SELECTED_ACTIONS="gateway" ;;
        3) SELECTED_ACTIONS="sandbox" ;;
        4) SELECTED_ACTIONS="credentials" ;;
        5) SELECTED_ACTIONS="install" ;;
        6) SELECTED_ACTIONS="all" ;;
        q|"") exit 0 ;;
    esac
}

show_menu() {
    case "$MENU_TOOL" in
        dialog)
            show_dialog_menu
            ;;
        whiptail)
            show_whiptail_menu
            ;;
        *)
            show_native_menu
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Action runners
# -----------------------------------------------------------------------------
run_audit() {
    print_header "Running Full Security Audit"

    local flags=""
    [ "$DRY_RUN" -eq 1 ] && flags="$flags --dry-run"
    [ "$VERBOSE" -eq 1 ] && flags="$flags --verbose"

    if [ -x "$SCRIPT_DIR/full-audit.sh" ]; then
        "$SCRIPT_DIR/full-audit.sh" $flags
    else
        print_error "full-audit.sh not found or not executable"
        return 1
    fi
}

run_gateway_hardening() {
    print_header "Hardening Gateway"

    local flags=""
    [ "$DRY_RUN" -eq 1 ] && flags="$flags --dry-run"
    [ "$VERBOSE" -eq 1 ] && flags="$flags --verbose"

    if [ -x "$SCRIPT_DIR/harden-gateway.sh" ]; then
        "$SCRIPT_DIR/harden-gateway.sh" $flags
    else
        print_error "harden-gateway.sh not found or not executable"
        return 1
    fi
}

run_sandbox_hardening() {
    print_header "Hardening Sandbox"

    local flags=""
    [ "$DRY_RUN" -eq 1 ] && flags="$flags --dry-run"
    [ "$VERBOSE" -eq 1 ] && flags="$flags --verbose"

    if [ -x "$SCRIPT_DIR/harden-sandbox.sh" ]; then
        "$SCRIPT_DIR/harden-sandbox.sh" $flags
    else
        print_error "harden-sandbox.sh not found or not executable"
        return 1
    fi
}

run_credentials_hardening() {
    print_header "Securing Credentials"

    local flags=""
    [ "$DRY_RUN" -eq 1 ] && flags="$flags --dry-run"
    [ "$VERBOSE" -eq 1 ] && flags="$flags --verbose"

    if [ -x "$SCRIPT_DIR/secure-credentials.sh" ]; then
        "$SCRIPT_DIR/secure-credentials.sh" $flags
    else
        print_error "secure-credentials.sh not found or not executable"
        return 1
    fi
}

run_install() {
    print_header "Installing Moltbot Hardener"

    local flags=""
    [ "$DRY_RUN" -eq 1 ] && flags="$flags --dry-run"
    [ "$VERBOSE" -eq 1 ] && flags="$flags --verbose"

    if [ -x "$SCRIPT_DIR/install.sh" ]; then
        "$SCRIPT_DIR/install.sh" $flags
    else
        print_error "install.sh not found or not executable"
        return 1
    fi
}

run_all() {
    print_header "Running All Hardening Steps"

    printf "${BOLD}This will run all hardening steps in sequence.${NC}\n\n"

    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        printf "Continue? [y/N]: "
        read -r confirm
        case "$confirm" in
            [yY]|[yY][eE][sS]) ;;
            *)
                print_info "Cancelled"
                return 0
                ;;
        esac
    fi

    local failed=0

    # Step 1: Install dependencies/binary
    run_with_spinner "Installing hardener" run_install || failed=$((failed + 1))

    # Step 2: Harden gateway
    run_with_spinner "Hardening gateway" run_gateway_hardening || failed=$((failed + 1))

    # Step 3: Harden sandbox
    run_with_spinner "Hardening sandbox" run_sandbox_hardening || failed=$((failed + 1))

    # Step 4: Secure credentials
    run_with_spinner "Securing credentials" run_credentials_hardening || failed=$((failed + 1))

    # Step 5: Final audit
    printf "\n"
    run_audit

    print_header "Hardening Complete"

    if [ "$failed" -eq 0 ]; then
        printf "${GREEN}${BOLD}All hardening steps completed successfully!${NC}\n"
    else
        printf "${YELLOW}${BOLD}Hardening completed with %d warning(s).${NC}\n" "$failed"
    fi
}

execute_action() {
    # Check if bot is running for non-audit actions
    case "$SELECTED_ACTIONS" in
        audit)
            # Audit is safe while bot is running
            print_info "Audit mode - safe to run with bot active"
            run_audit
            ;;
        gateway|sandbox|credentials|all)
            # These modify config - warn if bot is running
            warn_if_bot_running
            case "$SELECTED_ACTIONS" in
                gateway)
                    run_gateway_hardening
                    ;;
                sandbox)
                    run_sandbox_hardening
                    ;;
                credentials)
                    run_credentials_hardening
                    ;;
                all)
                    run_all
                    ;;
            esac
            ;;
        install)
            # Install doesn't need bot check
            run_install
            ;;
        *)
            print_error "Unknown action: $SELECTED_ACTIONS"
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Final report
# -----------------------------------------------------------------------------
show_final_report() {
    print_header "Session Complete"

    printf "Thank you for using Moltbot Hardener!\n\n"

    printf "${BOLD}Quick reference:${NC}\n"
    printf "  ${CYAN}•${NC} Run audit:        ${DIM}./scripts/full-audit.sh${NC}\n"
    printf "  ${CYAN}•${NC} Harden gateway:   ${DIM}./scripts/harden-gateway.sh${NC}\n"
    printf "  ${CYAN}•${NC} Harden sandbox:   ${DIM}./scripts/harden-sandbox.sh${NC}\n"
    printf "  ${CYAN}•${NC} Secure creds:     ${DIM}./scripts/secure-credentials.sh${NC}\n"
    printf "  ${CYAN}•${NC} Interactive menu: ${DIM}./scripts/run-hardener.sh${NC}\n"

    printf "\n${DIM}All scripts support --dry-run and --help flags.${NC}\n\n"
}

# -----------------------------------------------------------------------------
# Usage and main
# -----------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}Usage:${NC} $0 [OPTIONS] [ACTION]

${BOLD}Description:${NC}
    Interactive menu for Moltbot security hardening.

${BOLD}Actions:${NC}
    audit           Run full security audit
    gateway         Harden gateway configuration
    sandbox         Harden sandbox isolation
    credentials     Secure credential files
    install         Install moltbot-hardener binary
    all             Run all hardening steps

${BOLD}Options:${NC}
    -h, --help          Show this help message
    -n, --dry-run       Show what would be done without making changes
    -v, --verbose       Enable verbose output
    -y, --yes           Non-interactive mode (assume yes)

${BOLD}Examples:${NC}
    $0                  # Interactive menu
    $0 audit            # Run audit directly
    $0 -n all           # Dry-run all steps
    $0 -y gateway       # Harden gateway non-interactively

EOF
}

main() {
    # Parse arguments
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
            -y|--yes)
                NON_INTERACTIVE=1
                ;;
            audit|gateway|sandbox|credentials|install|all)
                SELECTED_ACTIONS="$1"
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    # Make scripts executable
    chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true

    # Show banner
    print_banner

    if [ "$DRY_RUN" -eq 1 ]; then
        print_warning "Running in dry-run mode - no changes will be made"
        printf "\n"
    fi

    # Check dependencies first
    check_dependencies

    # If no action specified, show menu
    if [ -z "$SELECTED_ACTIONS" ]; then
        while true; do
            if ! show_menu; then
                continue
            fi

            if [ -n "$SELECTED_ACTIONS" ]; then
                execute_action

                # Ask if user wants to continue
                if [ "$NON_INTERACTIVE" -eq 0 ]; then
                    printf "\n"
                    printf "Run another action? [Y/n]: "
                    read -r again
                    case "$again" in
                        [nN]|[nN][oO])
                            break
                            ;;
                    esac
                    SELECTED_ACTIONS=""
                else
                    break
                fi
            fi
        done
    else
        execute_action
    fi

    show_final_report
}

main "$@"
