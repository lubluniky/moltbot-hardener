#!/bin/sh
# install.sh - Main installer for moltbot-hardener
# Detects OS, installs dependencies, builds binary, and configures PATH

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
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="moltbot-hardener"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DRY_RUN=0
VERBOSE=0

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

detect_os() {
    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            ;;
        Linux*)
            OS="linux"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="$ID"
            elif [ -f /etc/redhat-release ]; then
                DISTRO="rhel"
            elif [ -f /etc/debian_version ]; then
                DISTRO="debian"
            else
                DISTRO="unknown"
            fi
            ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# Dependency installation
# -----------------------------------------------------------------------------
install_macos_deps() {
    local missing_deps=""

    for dep in go docker jq openssl; do
        if ! check_command "$dep"; then
            missing_deps="$missing_deps $dep"
        fi
    done

    if [ -n "$missing_deps" ]; then
        print_step "Installing missing dependencies:$missing_deps"

        if ! check_command brew; then
            print_error "Homebrew is required but not installed."
            print_info "Install it from https://brew.sh"
            exit 1
        fi

        for dep in $missing_deps; do
            case "$dep" in
                docker)
                    run_cmd brew install --cask docker
                    ;;
                *)
                    run_cmd brew install "$dep"
                    ;;
            esac
        done
    fi
}

install_linux_deps() {
    local missing_deps=""

    for dep in go docker jq openssl; do
        if ! check_command "$dep"; then
            missing_deps="$missing_deps $dep"
        fi
    done

    if [ -n "$missing_deps" ]; then
        print_step "Installing missing dependencies:$missing_deps"

        case "$DISTRO" in
            ubuntu|debian|pop)
                run_cmd sudo apt-get update
                for dep in $missing_deps; do
                    case "$dep" in
                        go)
                            run_cmd sudo apt-get install -y golang
                            ;;
                        docker)
                            run_cmd sudo apt-get install -y docker.io
                            run_cmd sudo systemctl enable docker
                            run_cmd sudo systemctl start docker
                            ;;
                        *)
                            run_cmd sudo apt-get install -y "$dep"
                            ;;
                    esac
                done
                ;;
            fedora|rhel|centos|rocky|alma)
                for dep in $missing_deps; do
                    case "$dep" in
                        go)
                            run_cmd sudo dnf install -y golang || run_cmd sudo yum install -y golang
                            ;;
                        docker)
                            run_cmd sudo dnf install -y docker || run_cmd sudo yum install -y docker
                            run_cmd sudo systemctl enable docker
                            run_cmd sudo systemctl start docker
                            ;;
                        *)
                            run_cmd sudo dnf install -y "$dep" || run_cmd sudo yum install -y "$dep"
                            ;;
                    esac
                done
                ;;
            arch|manjaro)
                for dep in $missing_deps; do
                    case "$dep" in
                        go)
                            run_cmd sudo pacman -S --noconfirm go
                            ;;
                        *)
                            run_cmd sudo pacman -S --noconfirm "$dep"
                            ;;
                    esac
                done
                ;;
            *)
                print_error "Unsupported Linux distribution: $DISTRO"
                print_info "Please install manually: $missing_deps"
                exit 1
                ;;
        esac
    fi
}

check_dependencies() {
    print_header "Checking Dependencies"

    local all_present=1

    for dep in go docker jq openssl; do
        if check_command "$dep"; then
            version=$("$dep" --version 2>/dev/null | head -n1 || echo "installed")
            print_success "$dep: $version"
        else
            print_warning "$dep: not found"
            all_present=0
        fi
    done

    if [ "$all_present" -eq 0 ]; then
        printf "\n"
        print_step "Installing missing dependencies..."

        case "$OS" in
            macos)
                install_macos_deps
                ;;
            linux)
                install_linux_deps
                ;;
        esac

        print_success "All dependencies installed"
    else
        print_success "All dependencies already present"
    fi
}

# -----------------------------------------------------------------------------
# Build process
# -----------------------------------------------------------------------------
build_binary() {
    print_header "Building $BINARY_NAME"

    if [ ! -f "$PROJECT_DIR/go.mod" ]; then
        print_error "go.mod not found in $PROJECT_DIR"
        print_info "Please run this script from the moltbot-hardener directory"
        exit 1
    fi

    print_step "Compiling Go binary..."

    cd "$PROJECT_DIR"

    if [ "$DRY_RUN" -eq 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} go build -o %s ./cmd/%s\n" "$BINARY_NAME" "$BINARY_NAME"
    else
        CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BINARY_NAME" "./cmd/$BINARY_NAME" 2>/dev/null || \
        CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BINARY_NAME" ./cmd/... 2>/dev/null || \
        go build -o "$BINARY_NAME" ./...
    fi

    if [ -f "$PROJECT_DIR/$BINARY_NAME" ] || [ "$DRY_RUN" -eq 1 ]; then
        print_success "Binary built successfully: $PROJECT_DIR/$BINARY_NAME"
    else
        print_error "Build failed"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Installation
# -----------------------------------------------------------------------------
install_binary() {
    print_header "Installing Binary"

    print_step "Installing to $INSTALL_DIR..."

    if [ ! -d "$INSTALL_DIR" ]; then
        run_cmd sudo mkdir -p "$INSTALL_DIR"
    fi

    run_cmd sudo cp "$PROJECT_DIR/$BINARY_NAME" "$INSTALL_DIR/"
    run_cmd sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"

    print_success "Installed to $INSTALL_DIR/$BINARY_NAME"

    # Check if INSTALL_DIR is in PATH
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            print_success "$INSTALL_DIR is already in PATH"
            ;;
        *)
            print_warning "$INSTALL_DIR is not in PATH"
            print_info "Add the following to your shell profile:"
            printf "\n    ${CYAN}export PATH=\"\$PATH:%s\"${NC}\n\n" "$INSTALL_DIR"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
verify_installation() {
    print_header "Verifying Installation"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "[DRY-RUN] Skipping verification"
        return 0
    fi

    if check_command "$BINARY_NAME"; then
        version=$("$BINARY_NAME" --version 2>/dev/null || echo "installed")
        print_success "$BINARY_NAME is available: $version"
    else
        print_warning "$BINARY_NAME not found in PATH"
        print_info "You may need to reload your shell or add $INSTALL_DIR to PATH"
    fi
}

# -----------------------------------------------------------------------------
# Usage and main
# -----------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Options:${NC}
    -h, --help          Show this help message
    -n, --dry-run       Show what would be done without making changes
    -v, --verbose       Enable verbose output
    -d, --install-dir   Installation directory (default: /usr/local/bin)

${BOLD}Examples:${NC}
    $0                  # Standard installation
    $0 --dry-run        # Preview installation steps
    $0 -d ~/.local/bin  # Install to custom directory

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
            -d|--install-dir)
                shift
                INSTALL_DIR="$1"
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    print_header "Moltbot Hardener Installer"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_warning "Running in dry-run mode - no changes will be made"
        printf "\n"
    fi

    detect_os
    print_info "Detected OS: $OS"
    if [ "$OS" = "linux" ]; then
        print_info "Distribution: $DISTRO"
    fi
    printf "\n"

    check_dependencies
    build_binary
    install_binary
    verify_installation

    print_header "Installation Complete"
    printf "${GREEN}${BOLD}moltbot-hardener has been installed successfully!${NC}\n\n"
    printf "Run ${CYAN}moltbot-hardener --help${NC} to get started.\n"
    printf "Or use ${CYAN}./scripts/run-hardener.sh${NC} for the interactive menu.\n\n"
}

main "$@"
