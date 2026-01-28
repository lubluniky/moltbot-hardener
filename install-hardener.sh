#!/bin/sh
# install-hardener.sh - Quick installer for moltbot-hardener
# Usage: curl -fsSL https://raw.githubusercontent.com/lubluniky/moltbot-hardener/main/install-hardener.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo "${BLUE}║${NC}           ${GREEN}Moltbot Hardener Installer${NC}                         ${BLUE}║${NC}"
echo "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "${BLUE}→${NC} Detected: $OS ($ARCH)"

# Check for Go
if ! command -v go >/dev/null 2>&1; then
    echo "${YELLOW}⚠${NC} Go is not installed."
    echo ""
    echo "Please install Go first:"
    if [ "$OS" = "Darwin" ]; then
        echo "  ${GREEN}brew install go${NC}"
    else
        echo "  ${GREEN}sudo apt install golang${NC}  (Debian/Ubuntu)"
        echo "  ${GREEN}sudo dnf install golang${NC}  (Fedora)"
    fi
    echo ""
    echo "Or download from: https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo "${GREEN}✓${NC} Go installed: $GO_VERSION"

# Create temp directory
INSTALL_DIR="${HOME}/.local/bin"
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "${BLUE}→${NC} Cloning repository..."
git clone --depth 1 https://github.com/lubluniky/moltbot-hardener.git >/dev/null 2>&1
cd moltbot-hardener

echo "${BLUE}→${NC} Building hardener..."
go build -ldflags="-s -w" -o hardener ./cmd/hardener

# Create install directory if needed
mkdir -p "$INSTALL_DIR"

# Install binary
echo "${BLUE}→${NC} Installing to $INSTALL_DIR/hardener..."
mv hardener "$INSTALL_DIR/hardener"
chmod +x "$INSTALL_DIR/hardener"

# Cleanup
cd /
rm -rf "$TMP_DIR"

# Check if in PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo ""
    echo "${YELLOW}⚠${NC} $INSTALL_DIR is not in your PATH."
    echo ""
    echo "Add this to your shell config (~/.bashrc, ~/.zshrc, etc.):"
    echo "  ${GREEN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
    echo "Or run hardener directly:"
    echo "  ${GREEN}$INSTALL_DIR/hardener${NC}"
else
    echo "${GREEN}✓${NC} Installed successfully!"
fi

echo ""
echo "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo "${GREEN}║${NC}                    Installation Complete!                     ${GREEN}║${NC}"
echo "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Quick start:"
echo "  ${BLUE}hardener audit${NC}              # Scan for vulnerabilities"
echo "  ${BLUE}hardener apply${NC}              # Apply security fixes"
echo "  ${BLUE}hardener --help${NC}             # Show all commands"
echo ""
echo "Before applying fixes, stop your moltbot gateway:"
echo "  ${YELLOW}moltbot gateway stop${NC}"
echo ""
