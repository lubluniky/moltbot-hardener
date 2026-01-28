#!/bin/sh
# secure-credentials.sh - Secure credential files and detect plaintext secrets
# Fixes file permissions, detects exposed secrets, warns about synced folders

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
NC='\033[0m'

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${MOLTBOT_CONFIG_DIR:-$HOME/.clawdbot}"
CREDS_DIR="$CONFIG_DIR/credentials"
SESSIONS_DIR="$CONFIG_DIR/sessions"
DRY_RUN=0
VERBOSE=0
FIX_PERMS=1
ISSUES_FOUND=0

# Patterns that indicate plaintext secrets
SECRET_PATTERNS="password|passwd|secret|token|api.?key|private.?key|access.?key|auth|credential|bearer"

# Cloud sync folders to check
SYNC_FOLDERS="Dropbox:Google Drive:OneDrive:iCloud Drive:Box Sync:Nextcloud"

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
    ISSUES_FOUND=1
}

print_error() {
    printf "${RED}✗${NC} %s\n" "$1"
    ISSUES_FOUND=1
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

# -----------------------------------------------------------------------------
# Permission checking and fixing
# -----------------------------------------------------------------------------
check_dir_permissions() {
    dir="$1"
    expected_mode="$2"
    name="$3"

    if [ ! -d "$dir" ]; then
        print_info "$name directory does not exist: $dir"
        return 0
    fi

    # Get current permissions (works on both macOS and Linux)
    if [ "$(uname -s)" = "Darwin" ]; then
        current_mode=$(stat -f "%Lp" "$dir" 2>/dev/null)
    else
        current_mode=$(stat -c "%a" "$dir" 2>/dev/null)
    fi

    if [ "$current_mode" = "$expected_mode" ]; then
        print_success "$name: $dir (mode $current_mode)"
    else
        print_warning "$name: $dir has mode $current_mode (expected $expected_mode)"

        if [ "$FIX_PERMS" -eq 1 ]; then
            run_cmd chmod "$expected_mode" "$dir"
            if [ "$DRY_RUN" -eq 0 ]; then
                print_success "Fixed permissions on $dir"
            fi
        fi
    fi
}

check_file_permissions() {
    file="$1"
    expected_mode="$2"
    name="$3"

    if [ ! -f "$file" ]; then
        return 0
    fi

    # Get current permissions
    if [ "$(uname -s)" = "Darwin" ]; then
        current_mode=$(stat -f "%Lp" "$file" 2>/dev/null)
    else
        current_mode=$(stat -c "%a" "$file" 2>/dev/null)
    fi

    if [ "$current_mode" = "$expected_mode" ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            print_success "$name: $(basename "$file") (mode $current_mode)"
        fi
    else
        print_warning "$name: $(basename "$file") has mode $current_mode (expected $expected_mode)"

        if [ "$FIX_PERMS" -eq 1 ]; then
            run_cmd chmod "$expected_mode" "$file"
            if [ "$DRY_RUN" -eq 0 ]; then
                print_success "Fixed permissions on $(basename "$file")"
            fi
        fi
    fi
}

fix_permissions() {
    print_header "Checking File Permissions"

    # Check main config directory (700)
    check_dir_permissions "$CONFIG_DIR" "700" "Config directory"

    # Check credentials directory (700)
    check_dir_permissions "$CREDS_DIR" "700" "Credentials directory"

    # Check sessions directory (700)
    check_dir_permissions "$SESSIONS_DIR" "700" "Sessions directory"

    # Check all credential files (600)
    if [ -d "$CREDS_DIR" ]; then
        print_step "Checking credential files..."
        for file in "$CREDS_DIR"/*; do
            if [ -f "$file" ]; then
                check_file_permissions "$file" "600" "Credential file"
            fi
        done
    fi

    # Check config file (600)
    check_file_permissions "$CONFIG_DIR/config.json" "600" "Config file"

    # Check session files (600)
    if [ -d "$SESSIONS_DIR" ]; then
        print_step "Checking session files..."
        session_count=0
        for file in "$SESSIONS_DIR"/*; do
            if [ -f "$file" ]; then
                check_file_permissions "$file" "600" "Session file"
                session_count=$((session_count + 1))
            fi
        done
        if [ "$session_count" -gt 0 ]; then
            print_info "Checked $session_count session files"
        fi
    fi

    # Check for world-readable files in config dir
    print_step "Scanning for world-readable files..."
    if [ -d "$CONFIG_DIR" ]; then
        world_readable=$(find "$CONFIG_DIR" -type f -perm -004 2>/dev/null | head -10)
        if [ -n "$world_readable" ]; then
            echo "$world_readable" | while read -r file; do
                print_error "World-readable: $file"
                if [ "$FIX_PERMS" -eq 1 ]; then
                    run_cmd chmod 600 "$file"
                fi
            done
        else
            print_success "No world-readable files found"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Plaintext secret detection
# -----------------------------------------------------------------------------
detect_plaintext_secrets() {
    print_header "Detecting Plaintext Secrets"

    local secrets_found=0

    # Check common locations for plaintext secrets
    locations_to_check="
        $HOME/.bashrc
        $HOME/.zshrc
        $HOME/.profile
        $HOME/.bash_profile
        $HOME/.zprofile
        $HOME/.env
        $HOME/.envrc
        $CONFIG_DIR/config.json
    "

    for loc in $locations_to_check; do
        if [ -f "$loc" ]; then
            print_step "Scanning $(basename "$loc")..."

            # Use grep to find potential secrets (case insensitive)
            matches=$(grep -inE "$SECRET_PATTERNS" "$loc" 2>/dev/null | grep -vE "^[[:space:]]*#" | head -5 || true)

            if [ -n "$matches" ]; then
                print_warning "Potential secrets found in $loc:"
                echo "$matches" | while read -r line; do
                    line_num=$(echo "$line" | cut -d: -f1)
                    # Mask the actual values
                    masked=$(echo "$line" | sed -E 's/(password|secret|token|key|auth)[^=]*=.*/\1=*****REDACTED*****/gi')
                    printf "    ${YELLOW}Line %s:${NC} %s\n" "$line_num" "$masked"
                done
                secrets_found=1
            fi
        fi
    done

    # Check for .env files in common project locations
    print_step "Scanning for .env files..."
    env_files=$(find "$HOME" -maxdepth 3 -name ".env" -o -name ".env.local" -o -name ".env.production" 2>/dev/null | head -20 || true)

    if [ -n "$env_files" ]; then
        env_count=$(echo "$env_files" | wc -l | tr -d ' ')
        print_warning "Found $env_count .env file(s) in home directory"

        echo "$env_files" | while read -r env_file; do
            if [ -f "$env_file" ]; then
                # Check permissions
                if [ "$(uname -s)" = "Darwin" ]; then
                    mode=$(stat -f "%Lp" "$env_file" 2>/dev/null)
                else
                    mode=$(stat -c "%a" "$env_file" 2>/dev/null)
                fi

                if [ "$mode" != "600" ]; then
                    print_warning "  $env_file (mode $mode - should be 600)"
                    if [ "$FIX_PERMS" -eq 1 ]; then
                        run_cmd chmod 600 "$env_file"
                    fi
                else
                    if [ "$VERBOSE" -eq 1 ]; then
                        print_info "  $env_file (mode $mode - OK)"
                    fi
                fi
            fi
        done
    else
        print_success "No .env files found in common locations"
    fi

    # Check for SSH keys with weak permissions
    print_step "Checking SSH key permissions..."
    if [ -d "$HOME/.ssh" ]; then
        for key in "$HOME/.ssh"/id_* "$HOME/.ssh"/*.pem; do
            if [ -f "$key" ] && echo "$key" | grep -qvE "\.pub$"; then
                if [ "$(uname -s)" = "Darwin" ]; then
                    mode=$(stat -f "%Lp" "$key" 2>/dev/null)
                else
                    mode=$(stat -c "%a" "$key" 2>/dev/null)
                fi

                if [ "$mode" != "600" ] && [ "$mode" != "400" ]; then
                    print_warning "SSH key with weak permissions: $key (mode $mode)"
                    if [ "$FIX_PERMS" -eq 1 ]; then
                        run_cmd chmod 600 "$key"
                    fi
                fi
            fi
        done
        print_success "SSH key permissions checked"
    fi

    if [ "$secrets_found" -eq 1 ]; then
        printf "\n"
        print_warning "Recommendations:"
        print_info "  1. Use environment variables loaded from secure sources"
        print_info "  2. Use a secrets manager (1Password, Vault, etc.)"
        print_info "  3. Never commit secrets to version control"
        print_info "  4. Use 'moltbot config set' instead of editing config directly"
    else
        print_success "No obvious plaintext secrets detected"
    fi
}

# -----------------------------------------------------------------------------
# Cloud sync folder detection
# -----------------------------------------------------------------------------
check_synced_folders() {
    print_header "Checking Cloud Sync Exposure"

    local exposure_found=0

    # Check if config directory is inside a synced folder
    config_realpath=$(cd "$CONFIG_DIR" 2>/dev/null && pwd -P || echo "$CONFIG_DIR")

    IFS=':'
    for sync_folder in $SYNC_FOLDERS; do
        sync_path="$HOME/$sync_folder"
        if [ -d "$sync_path" ]; then
            sync_realpath=$(cd "$sync_path" 2>/dev/null && pwd -P || echo "$sync_path")

            # Check if config is inside sync folder
            case "$config_realpath" in
                "$sync_realpath"*)
                    print_error "Config directory is inside $sync_folder!"
                    print_info "  Config: $CONFIG_DIR"
                    print_info "  Sync folder: $sync_path"
                    exposure_found=1
                    ;;
            esac

            # Check for credential files in sync folder
            if [ "$VERBOSE" -eq 1 ]; then
                print_step "Scanning $sync_folder for sensitive files..."
            fi

            sensitive=$(find "$sync_path" -maxdepth 3 \( \
                -name "*.pem" -o \
                -name "*.key" -o \
                -name "id_rsa*" -o \
                -name "id_ed25519*" -o \
                -name ".env*" -o \
                -name "credentials*" -o \
                -name "*secret*" -o \
                -name "*token*" \
            \) 2>/dev/null | head -10 || true)

            if [ -n "$sensitive" ]; then
                print_warning "Sensitive files found in $sync_folder:"
                echo "$sensitive" | while read -r file; do
                    printf "    ${YELLOW}→${NC} %s\n" "$file"
                done
                exposure_found=1
            fi
        fi
    done
    unset IFS

    # Check for symlinks pointing to synced folders
    print_step "Checking for symlinks to sync folders..."

    if [ -L "$CONFIG_DIR" ]; then
        link_target=$(readlink -f "$CONFIG_DIR" 2>/dev/null || readlink "$CONFIG_DIR")
        IFS=':'
        for sync_folder in $SYNC_FOLDERS; do
            sync_path="$HOME/$sync_folder"
            case "$link_target" in
                "$sync_path"*|*"$sync_folder"*)
                    print_error "Config directory symlinks to $sync_folder!"
                    print_info "  Link: $CONFIG_DIR -> $link_target"
                    exposure_found=1
                    ;;
            esac
        done
        unset IFS
    fi

    # Check .gitignore for credentials directory
    print_step "Checking .gitignore coverage..."

    if [ -d "$HOME/.clawdbot" ]; then
        parent_git=$(find "$HOME" -maxdepth 2 -name ".git" -type d 2>/dev/null | head -1)
        if [ -n "$parent_git" ]; then
            git_root=$(dirname "$parent_git")
            gitignore="$git_root/.gitignore"

            if [ -f "$gitignore" ]; then
                if grep -qE "\.clawdbot|clawdbot" "$gitignore" 2>/dev/null; then
                    print_success ".clawdbot is in .gitignore"
                else
                    print_warning ".clawdbot may not be properly gitignored"
                fi
            fi
        fi
    fi

    if [ "$exposure_found" -eq 0 ]; then
        print_success "No cloud sync exposure detected"
    else
        printf "\n"
        print_warning "Recommendations:"
        print_info "  1. Move config directory outside of synced folders"
        print_info "  2. Add credentials to sync folder exclusion list"
        print_info "  3. Use: MOLTBOT_CONFIG_DIR=/path/outside/sync"
    fi
}

# -----------------------------------------------------------------------------
# Git exposure check
# -----------------------------------------------------------------------------
check_git_exposure() {
    print_header "Checking Git Repository Exposure"

    # Check if config dir is in a git repo
    if [ -d "$CONFIG_DIR" ]; then
        if git -C "$CONFIG_DIR" rev-parse --git-dir >/dev/null 2>&1; then
            print_error "Config directory is inside a git repository!"
            git_root=$(git -C "$CONFIG_DIR" rev-parse --show-toplevel 2>/dev/null)
            print_info "  Git root: $git_root"

            # Check if it's properly ignored
            if git -C "$CONFIG_DIR" check-ignore -q "$CONFIG_DIR" 2>/dev/null; then
                print_success "  Directory is gitignored"
            else
                print_warning "  Directory may NOT be properly gitignored!"
                print_info "  Add to .gitignore: .clawdbot/"
            fi
        else
            print_success "Config directory is not in a git repository"
        fi
    fi

    # Check for committed secrets in git history
    print_step "Checking for secrets in recent commits..."

    if check_command git; then
        # Find git repos in home directory
        repos=$(find "$HOME" -maxdepth 3 -name ".git" -type d 2>/dev/null | head -5 || true)

        if [ -n "$repos" ]; then
            echo "$repos" | while read -r git_dir; do
                repo_root=$(dirname "$git_dir")
                repo_name=$(basename "$repo_root")

                # Check recent commits for secret patterns
                secrets_in_history=$(git -C "$repo_root" log --oneline -20 --all -p 2>/dev/null | \
                    grep -iE "(password|secret|token|api.?key).*=" | head -3 || true)

                if [ -n "$secrets_in_history" ]; then
                    print_warning "Potential secrets in git history: $repo_name"
                fi
            done
        fi
    fi

    print_success "Git exposure check complete"
}

# -----------------------------------------------------------------------------
# Summary report
# -----------------------------------------------------------------------------
generate_summary() {
    print_header "Security Summary"

    if [ "$ISSUES_FOUND" -eq 0 ]; then
        printf "${GREEN}${BOLD}All credential security checks passed!${NC}\n\n"
        print_success "File permissions are correct"
        print_success "No plaintext secrets detected"
        print_success "No cloud sync exposure"
    else
        printf "${YELLOW}${BOLD}Some security issues were found.${NC}\n\n"
        print_info "Review the warnings above and take appropriate action."

        if [ "$FIX_PERMS" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
            print_info "Permission issues have been automatically fixed."
        fi
    fi

    printf "\n"
    print_info "Security tips:"
    printf "  ${CYAN}1.${NC} Use 'moltbot config set' for configuration changes\n"
    printf "  ${CYAN}2.${NC} Store API keys in environment variables\n"
    printf "  ${CYAN}3.${NC} Use a password manager for secrets\n"
    printf "  ${CYAN}4.${NC} Regularly rotate sensitive tokens\n"
    printf "  ${CYAN}5.${NC} Review access logs periodically\n"
}

# -----------------------------------------------------------------------------
# Usage and main
# -----------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Description:${NC}
    Secures credential files and detects potential secrets exposure:
    - Fixes file permissions (600 for files, 700 for directories)
    - Detects plaintext secrets in config files
    - Warns about cloud sync folder exposure
    - Checks git repository exposure

${BOLD}Options:${NC}
    -h, --help          Show this help message
    -n, --dry-run       Show what would be done without making changes
    -v, --verbose       Enable verbose output
    --no-fix            Don't automatically fix permissions
    --config-dir DIR    Specify config directory (default: ~/.clawdbot)

${BOLD}Examples:${NC}
    $0                  # Check and fix all issues
    $0 --dry-run        # Preview changes
    $0 --no-fix         # Check only, don't fix

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
            --no-fix)
                FIX_PERMS=0
                ;;
            --config-dir)
                shift
                CONFIG_DIR="$1"
                CREDS_DIR="$CONFIG_DIR/credentials"
                SESSIONS_DIR="$CONFIG_DIR/sessions"
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    print_header "Credential Security Check"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_warning "Running in dry-run mode - no changes will be made"
        printf "\n"
    fi

    print_info "Config directory: $CONFIG_DIR"
    printf "\n"

    fix_permissions
    detect_plaintext_secrets
    check_synced_folders
    check_git_exposure
    generate_summary
}

main "$@"
