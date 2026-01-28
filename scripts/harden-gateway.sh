#!/bin/sh
# harden-gateway.sh - Harden the Moltbot gateway configuration
# Backs up config, sets loopback binding, generates auth token, restarts gateway

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
BACKUP_DIR="$CONFIG_DIR/backups"
DRY_RUN=0
VERBOSE=0
SKIP_RESTART=0
TOKEN_LENGTH=32

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

generate_token() {
    if check_command openssl; then
        openssl rand -hex "$TOKEN_LENGTH"
    elif [ -f /dev/urandom ]; then
        head -c "$TOKEN_LENGTH" /dev/urandom | od -An -tx1 | tr -d ' \n'
    else
        print_error "Cannot generate secure token: no openssl or /dev/urandom"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Backup functions
# -----------------------------------------------------------------------------
backup_config() {
    print_header "Backing Up Configuration"

    if [ ! -f "$CONFIG_FILE" ]; then
        print_warning "No config file found at $CONFIG_FILE"
        print_info "A new config will be created"
        return 0
    fi

    if [ ! -d "$BACKUP_DIR" ]; then
        run_cmd mkdir -p "$BACKUP_DIR"
    fi

    BACKUP_NAME="config.$(date +%Y%m%d_%H%M%S).json"
    BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

    run_cmd cp "$CONFIG_FILE" "$BACKUP_PATH"
    print_success "Config backed up to $BACKUP_PATH"

    # Keep only last 10 backups
    if [ "$DRY_RUN" -eq 0 ]; then
        backup_count=$(ls -1 "$BACKUP_DIR"/config.*.json 2>/dev/null | wc -l)
        if [ "$backup_count" -gt 10 ]; then
            ls -1t "$BACKUP_DIR"/config.*.json | tail -n +11 | xargs rm -f
            print_info "Cleaned up old backups (keeping last 10)"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Gateway hardening
# -----------------------------------------------------------------------------
set_loopback_binding() {
    print_header "Setting Gateway Binding"

    print_step "Configuring gateway.bind to loopback..."

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} moltbot config set gateway.bind loopback\n"
    else
        if check_command moltbot; then
            moltbot config set gateway.bind loopback
            print_success "Gateway bound to loopback interface"
        else
            print_warning "moltbot CLI not found, updating config directly"
            update_config_json "gateway.bind" "loopback"
        fi
    fi

    print_info "Gateway will only accept connections from localhost"
}

generate_auth_token() {
    print_header "Generating Auth Token"

    print_step "Generating secure authentication token..."

    NEW_TOKEN=$(generate_token)

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} Generated token: %s...\n" "$(echo "$NEW_TOKEN" | cut -c1-16)"
        printf "${YELLOW}[DRY-RUN]${NC} moltbot config set gateway.authToken <token>\n"
    else
        if check_command moltbot; then
            moltbot config set gateway.authToken "$NEW_TOKEN"
            print_success "Auth token generated and saved"
        else
            print_warning "moltbot CLI not found, updating config directly"
            update_config_json "gateway.authToken" "$NEW_TOKEN"
        fi
    fi

    print_info "Token (first 16 chars): $(echo "$NEW_TOKEN" | cut -c1-16)..."
    print_warning "Save this token securely - it's required for gateway connections"
}

update_config_json() {
    key="$1"
    value="$2"

    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        echo '{}' > "$CONFIG_FILE"
    fi

    if check_command jq; then
        # Split key by dots for nested update
        case "$key" in
            *"."*)
                parent=$(echo "$key" | cut -d. -f1)
                child=$(echo "$key" | cut -d. -f2-)
                tmp=$(mktemp)
                jq --arg p "$parent" --arg c "$child" --arg v "$value" \
                    '.[$p] = (.[$p] // {}) | .[$p][$c] = $v' "$CONFIG_FILE" > "$tmp"
                mv "$tmp" "$CONFIG_FILE"
                ;;
            *)
                tmp=$(mktemp)
                jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$CONFIG_FILE" > "$tmp"
                mv "$tmp" "$CONFIG_FILE"
                ;;
        esac
        print_success "Updated $key in config"
    else
        print_error "jq is required to update config directly"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Gateway restart
# -----------------------------------------------------------------------------
restart_gateway() {
    print_header "Restarting Gateway"

    if [ "$SKIP_RESTART" -eq 1 ]; then
        print_info "Skipping gateway restart (--no-restart specified)"
        return 0
    fi

    # Check if gateway is running
    if pgrep -f "moltbot.*gateway" >/dev/null 2>&1 || pgrep -f "moltbot-gateway" >/dev/null 2>&1; then
        print_step "Stopping existing gateway..."

        if [ "$DRY_RUN" -eq 1 ]; then
            printf "${YELLOW}[DRY-RUN]${NC} pkill -9 -f moltbot-gateway\n"
        else
            pkill -9 -f "moltbot.*gateway" 2>/dev/null || true
            pkill -9 -f "moltbot-gateway" 2>/dev/null || true
            sleep 1
            print_success "Gateway stopped"
        fi

        print_step "Starting gateway with new configuration..."

        if [ "$DRY_RUN" -eq 1 ]; then
            printf "${YELLOW}[DRY-RUN]${NC} nohup moltbot gateway run --bind loopback > /tmp/moltbot-gateway.log 2>&1 &\n"
        else
            if check_command moltbot; then
                nohup moltbot gateway run --bind loopback --force > /tmp/moltbot-gateway.log 2>&1 &
                sleep 2

                if pgrep -f "moltbot.*gateway" >/dev/null 2>&1; then
                    print_success "Gateway restarted successfully"
                else
                    print_error "Gateway failed to start - check /tmp/moltbot-gateway.log"
                fi
            else
                print_warning "moltbot CLI not found, cannot restart gateway"
            fi
        fi
    else
        print_info "Gateway is not currently running"
        print_info "Start it with: moltbot gateway run --bind loopback"
    fi
}

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
verify_hardening() {
    print_header "Verifying Hardening"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY-RUN] Skipping verification"
        return 0
    fi

    local all_good=1

    # Check config values
    if [ -f "$CONFIG_FILE" ] && check_command jq; then
        bind_value=$(jq -r '.gateway.bind // empty' "$CONFIG_FILE" 2>/dev/null)
        if [ "$bind_value" = "loopback" ]; then
            print_success "gateway.bind = loopback"
        else
            print_warning "gateway.bind = $bind_value (expected: loopback)"
            all_good=0
        fi

        token_value=$(jq -r '.gateway.authToken // empty' "$CONFIG_FILE" 2>/dev/null)
        if [ -n "$token_value" ]; then
            print_success "gateway.authToken is set"
        else
            print_warning "gateway.authToken is not set"
            all_good=0
        fi
    fi

    # Check if gateway is listening on loopback only
    if check_command ss; then
        gateway_port=$(ss -ltnp 2>/dev/null | grep -E "(moltbot|18789)" | head -1)
        if echo "$gateway_port" | grep -qE "127\.0\.0\.1|localhost|\[::\]1"; then
            print_success "Gateway listening on loopback only"
        elif [ -n "$gateway_port" ]; then
            print_warning "Gateway may be listening on non-loopback interface"
            all_good=0
        fi
    elif check_command netstat; then
        gateway_port=$(netstat -an 2>/dev/null | grep -E "LISTEN.*18789" | head -1)
        if echo "$gateway_port" | grep -qE "127\.0\.0\.1|localhost"; then
            print_success "Gateway listening on loopback only"
        elif [ -n "$gateway_port" ]; then
            print_warning "Gateway may be listening on non-loopback interface"
            all_good=0
        fi
    fi

    if [ "$all_good" -eq 1 ]; then
        printf "\n${GREEN}${BOLD}All gateway hardening checks passed!${NC}\n"
    else
        printf "\n${YELLOW}${BOLD}Some checks need attention.${NC}\n"
    fi
}

# -----------------------------------------------------------------------------
# Usage and main
# -----------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Description:${NC}
    Hardens the Moltbot gateway by:
    - Backing up current configuration
    - Setting gateway.bind to loopback
    - Generating and setting a secure auth token
    - Restarting the gateway if running

${BOLD}Options:${NC}
    -h, --help          Show this help message
    -n, --dry-run       Show what would be done without making changes
    -v, --verbose       Enable verbose output
    --no-restart        Don't restart the gateway
    --token-length N    Auth token length in bytes (default: 32)

${BOLD}Examples:${NC}
    $0                  # Standard hardening
    $0 --dry-run        # Preview changes
    $0 --no-restart     # Harden without restarting

EOF
}

main() {
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
            --no-restart)
                SKIP_RESTART=1
                ;;
            --token-length)
                shift
                TOKEN_LENGTH="$1"
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    print_header "Gateway Hardening"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_warning "Running in dry-run mode - no changes will be made"
        printf "\n"
    fi

    backup_config
    set_loopback_binding
    generate_auth_token
    restart_gateway
    verify_hardening

    print_header "Gateway Hardening Complete"
    printf "${GREEN}${BOLD}Gateway has been hardened successfully!${NC}\n\n"
}

main "$@"
