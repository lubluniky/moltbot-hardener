# Moltbot Hardener

A comprehensive security hardening tool for [Moltbot](https://github.com/moltbot/moltbot) installations. Scans for vulnerabilities, applies fixes, and helps you run your AI gateway securely.

```
 _____ _____ __    _____ _____ _____ _____
|     |     |  |  |_   _| __  |     |_   _|
| | | |  |  |  |__  | | | __ -|  |  | | |
|_|_|_|_____|_____| |_| |_____|_____| |_|
        H A R D E N E R  v1.0.0

[====================================] 100%
Scanning moltbot configuration...

CRITICAL  V01 Gateway Exposure
          Gateway bound to 0.0.0.0 without authentication
          Fix: Set gateway.bind to loopback or configure auth

WARNING   V02 DM Policy Open
          WhatsApp DMs are open to anyone
          Fix: Set dmPolicy to pairing or allowlist

INFO      V09 Audit Logging Disabled
          No audit logging configured
          Fix: Enable logging.file for audit trail

Found: 3 critical, 5 warnings, 2 info
Run with --fix to apply automatic remediations
```

---

## ⚠️ IMPORTANT: When to Run Hardener

### TL;DR

| Action | Bot Running? | Restart Required? |
|--------|-------------|-------------------|
| `audit` (scan only) | ✅ Yes, safe | No |
| `apply` (fix issues) | ❌ **Stop bot first** | **Yes** |

### Detailed Explanation

#### 🔍 Scanning (`hardener audit`)
**Can run anytime** - even with bot running.
- Only reads config files and checks permissions
- Does not modify anything
- Safe to run in production

```bash
# Safe to run while bot is active
./hardener audit
./hardener audit --json > report.json
```

#### 🔧 Applying Fixes (`hardener apply`)
**Stop the bot first**, then apply, then restart.

**Why?**
1. **Gateway changes** (V01, V20, V23) - bind address and auth token are read at startup only
2. **Sandbox changes** (V03, V07, V11) - Docker settings cached on agent start
3. **Race conditions** - bot may overwrite config while hardener is editing
4. **File locks** - session/credential files may be locked by running process

### Recommended Workflow

```bash
# Step 1: Stop the gateway (uses launchd on macOS, systemd on Linux)
moltbot gateway stop

# Step 2: Verify gateway is stopped
moltbot gateway status

# Step 3: Run hardener
./hardener audit                    # Check what needs fixing
./hardener apply --interactive      # Apply fixes with confirmation

# Step 4: Restart the gateway
moltbot gateway start
# Or restart (stop + start):
moltbot gateway restart
```

### Quick One-Liner (Stop → Harden → Start)

```bash
# Using official moltbot commands (recommended)
moltbot gateway stop && ./hardener apply --yes && moltbot gateway start

# macOS alternative (if launchd service not installed)
pkill -f moltbot-gateway; sleep 2; ./hardener apply --yes; moltbot gateway run &

# Linux (systemd)
sudo systemctl stop moltbot && ./hardener apply --yes && sudo systemctl start moltbot
```

### Gateway Service Management

Moltbot uses system service managers:
- **macOS**: launchd (`~/Library/LaunchAgents/bot.molt.gateway.plist`)
- **Linux**: systemd (if installed via `moltbot gateway install`)

```bash
# Install gateway as system service
moltbot gateway install

# Service lifecycle
moltbot gateway start
moltbot gateway stop
moltbot gateway restart
moltbot gateway status

# Uninstall service
moltbot gateway uninstall
```

### What If I Apply While Bot Is Running?

| What Happens | Risk Level |
|--------------|-----------|
| Config changes won't take effect until restart | ⚠️ Medium |
| Gateway keeps old bind/auth settings | 🔴 High - still vulnerable |
| File permission changes apply immediately | ✅ Low |
| Credential files may fail to update (locked) | ⚠️ Medium |

**Bottom line:** Hardener won't crash your bot, but fixes won't fully apply until restart.

---

## Quick Start

```bash
# One-liner install
curl -fsSL https://raw.githubusercontent.com/lubluniky/moltbot-hardener/main/install-hardener.sh | bash

# Run audit (safe while bot is running)
hardener audit

# Apply fixes (stop bot first!)
moltbot gateway stop
hardener apply
moltbot gateway start
```

## Features

- Scans 26 known vulnerabilities across gateway, channels, tools, and filesystem
- Interactive TUI with real-time scanning progress
- Automatic remediation for most issues
- Generates detailed security reports
- Integrates with existing `moltbot security audit`

## Vulnerabilities Detected

| ID | Name | Severity | Auto-Fix |
|----|------|----------|----------|
| V01 | [Gateway Exposure](docs/vulnerabilities/V01-gateway-exposure.md) | Critical | Yes |
| V02 | [DM Policy Open](docs/vulnerabilities/V02-dm-policy-open.md) | Critical | Yes |
| V03 | [Sandbox Disabled](docs/vulnerabilities/V03-sandbox-disabled.md) | Critical | ⚠️ Partial |
| V04 | [Plaintext Credentials](docs/vulnerabilities/V04-plaintext-credentials.md) | Critical | Yes |
| V05 | [Prompt Injection Surface](docs/vulnerabilities/V05-prompt-injection.md) | Critical | ⚠️ Partial |
| V06 | [Dangerous Commands Enabled](docs/vulnerabilities/V06-dangerous-commands.md) | Critical | Yes |
| V07 | [No Network Isolation](docs/vulnerabilities/V07-no-network-isolation.md) | High | Yes |
| V08 | [Elevated Tool Access](docs/vulnerabilities/V08-elevated-tool-access.md) | Critical | Yes |
| V09 | [No Audit Logging](docs/vulnerabilities/V09-no-audit-logging.md) | Medium | Yes |
| V10 | [Weak Pairing Codes](docs/vulnerabilities/V10-weak-pairing-codes.md) | Medium | Yes |
| V11 | [Unrestricted Bind Mounts](docs/vulnerabilities/V11-unrestricted-bind-mounts.md) | High | Yes |
| V12 | [DNS Poisoning Risk](docs/vulnerabilities/V12-dns-poisoning.md) | Medium | Yes |
| V13 | [Shell Injection Vectors](docs/vulnerabilities/V13-shell-injection.md) | Critical | ⚠️ Partial |
| V14 | [DM Scope Context Leak](docs/vulnerabilities/V14-dm-scope-context-leak.md) | High | Yes |
| V15 | [Pairing DoS](docs/vulnerabilities/V15-pairing-dos.md) | Medium | Yes |
| V16 | [Browser Sandbox Escape](docs/vulnerabilities/V16-browser-sandbox-escape.md) | Critical | Yes |
| V17 | [World-Readable Config](docs/vulnerabilities/V17-world-readable-config.md) | Critical | Yes |
| V18 | [State Directory Exposure](docs/vulnerabilities/V18-state-dir-exposure.md) | Critical | Yes |
| V19 | [Synced Folder Leak](docs/vulnerabilities/V19-synced-folder-leak.md) | High | ⚠️ Partial |
| V20 | [Tailscale Funnel Exposure](docs/vulnerabilities/V20-tailscale-funnel.md) | Critical | Yes |
| V21 | [Plugin Trust Boundary](docs/vulnerabilities/V21-plugin-trust.md) | High | ⚠️ Partial |
| V22 | [Legacy Model Risk](docs/vulnerabilities/V22-legacy-model-risk.md) | High | ⚠️ Partial |
| V23 | [Control UI Insecure Auth](docs/vulnerabilities/V23-control-ui-insecure.md) | Critical | Yes |
| V24 | [Hooks Token Reuse](docs/vulnerabilities/V24-hooks-token-reuse.md) | Medium | Yes |
| V25 | [Group Policy Open](docs/vulnerabilities/V25-group-policy-open.md) | Critical | Yes |
| V26 | [mDNS Information Disclosure](docs/vulnerabilities/V26-mdns-disclosure.md) | Medium | Yes |

### Understanding "Partial" Auto-Fix

Some vulnerabilities are marked **Partial** because automatic fixing could break your bot:

| ID | Why Partial | What Hardener Does |
|----|-------------|-------------------|
| **V03** Sandbox Disabled | Enabling sandbox may break custom bind mounts or setup commands | Prompts for confirmation, shows affected mounts |
| **V05** Prompt Injection | Requires code changes in moltbot itself, not just config | Reports issue, provides manual fix guide |
| **V13** Shell Injection | `setupCommand` may be legitimate (e.g., `npm install`) | Warns about dangerous patterns, doesn't delete |
| **V19** Synced Folder | Moving credentials could cause data loss | Detects and warns, user must move manually |
| **V21** Plugin Trust | Unknown which plugins user actually needs | Asks which plugins to allow |
| **V22** Legacy Model | User's choice which AI model to use | Warns about models without safety features |

**Interactive Mode** (`--interactive` or `-i`) will prompt you for each partial fix:

```bash
./hardener apply --interactive

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 V03: Sandbox Disabled
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sandbox is currently disabled. Enabling it will isolate
code execution in Docker containers.

⚠️  Found 2 bind mounts that may be affected:
   - /home/user/project:/app
   - /tmp/cache:/cache

What would you like to do?
  [1] Apply this fix
  [2] Skip this fix
  [3] Apply all remaining fixes
  [4] Abort

Select option: _
```

## Installation

### Quick Install (macOS / Linux)

```bash
# One-liner: downloads, builds, and installs to ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/lubluniky/moltbot-hardener/main/install-hardener.sh | bash
```

**Requirements:** Go 1.21+ (`brew install go` or `apt install golang`)

### From Source

```bash
git clone https://github.com/lubluniky/moltbot-hardener.git
cd moltbot-hardener
go build -o hardener ./cmd/hardener

# Run directly
./hardener audit

# Or install to PATH
sudo mv hardener /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/lubluniky/moltbot-hardener/cmd/hardener@latest
```

## Usage

### Basic Scan

```bash
# Scan for vulnerabilities (safe while bot is running)
hardener audit

# JSON output for CI/CD
hardener audit --json

# Verbose output
hardener audit --verbose

# List all available checks
hardener list
```

### Apply Fixes

```bash
# IMPORTANT: Stop the gateway first!
moltbot gateway stop

# Interactive mode (prompts for each fix)
hardener apply

# Auto-apply all fixes
hardener apply --yes

# Dry-run (show what would be fixed)
hardener apply --dry-run

# Force apply even if bot is running (not recommended)
hardener apply --force

# Restart gateway after fixes
moltbot gateway start
```

### Fix Specific Vulnerability

```bash
# Fix a single vulnerability by ID
hardener fix V01
hardener fix V03 --dry-run
```

### Generate Reports

```bash
# JSON report
hardener audit --json > report.json

# Check dependencies
hardener check-deps
```

### Filter Checks

```bash
# Skip specific checks
hardener audit --skip V01,V02

# Run only specific checks
hardener audit --only V03,V04,V05
```

### Firewall Management

```bash
# Check firewall status
hardener firewall status

# Harden firewall (requires sudo)
hardener firewall harden
```

### Bash Scripts

The hardener also includes standalone bash scripts:

```bash
# Full security audit
./scripts/full-audit.sh

# Harden specific components
./scripts/harden-gateway.sh
./scripts/harden-sandbox.sh
./scripts/secure-credentials.sh

# Interactive menu
./scripts/run-hardener.sh
```

## TUI Interface

The hardener includes an interactive terminal UI:

```
+------------------------------------------------------------------+
|  MOLTBOT HARDENER v1.0.0                              [?] Help   |
+------------------------------------------------------------------+
|                                                                  |
|  Scan Progress                                                   |
|  [========================================] 100%                 |
|                                                                  |
|  +------+----------+------------------------------------------+  |
|  | Sev  | ID       | Title                                    |  |
|  +------+----------+------------------------------------------+  |
|  | CRIT | V01      | Gateway Exposure                         |  |
|  | CRIT | V08      | Elevated Tool Access                     |  |
|  | HIGH | V14      | DM Scope Context Leak                    |  |
|  | WARN | V09      | No Audit Logging                         |  |
|  | INFO | V22      | Legacy Model Risk                        |  |
|  +------+----------+------------------------------------------+  |
|                                                                  |
|  Summary: 2 Critical | 1 High | 1 Warning | 1 Info               |
|                                                                  |
|  [F] Fix Selected  [A] Fix All  [R] Refresh  [Q] Quit            |
+------------------------------------------------------------------+
```

Use arrow keys to navigate, Enter to view details, F to fix selected.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed information about how the hardener works.

## Integration with Moltbot

The hardener complements `moltbot security audit`:

```bash
# Native moltbot command (built-in)
moltbot security audit

# Hardener (extended checks + TUI)
hardener audit
hardener apply
```

The hardener performs additional checks not in the built-in audit:
- Deeper filesystem permission analysis
- Cross-reference vulnerability chains
- Network exposure probing
- Firewall configuration

## Secure Defaults Template

For a hardened configuration template, see [configs/secure-defaults.yaml](configs/secure-defaults.yaml).

You can use it as reference when running:

```bash
hardener apply --yes
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / No critical findings |
| 1 | Error or critical findings present |

## Contributing

Contributions welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Add tests for new checks
4. Submit a pull request

### Adding New Vulnerability Checks

1. Create a check function in `pkg/audit/checks.go`
2. Add documentation in `docs/vulnerabilities/V##-name.md`
3. Register in the scanner
4. Add tests in `pkg/audit/*_test.go`

## Security Policy

Found a vulnerability in the hardener itself? Please open an issue on GitHub.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built for the [Moltbot](https://github.com/moltbot/moltbot) project
- Security checks based on real-world incidents and the moltbot threat model
- TUI powered by [bubbletea](https://github.com/charmbracelet/bubbletea)

---

*"Security is a process, not a product. The hardener helps you stay on top of it."*
