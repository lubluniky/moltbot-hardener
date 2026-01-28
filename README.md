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

## Quick Start

```bash
# Clone
git clone https://github.com/lubluniky/moltbot-hardener.git
cd moltbot-hardener

# Build
go build -o hardener ./cmd/hardener

# Scan (safe while bot running)
./hardener audit

# Fix (stop bot first!)
moltbot gateway stop
./hardener apply --yes
moltbot gateway start
```

**Requirements:** Go 1.21+ (`brew install go` or `apt install golang`)

---

## When to Run Hardener

| Action | Bot Running? | Restart Required? |
|--------|-------------|-------------------|
| `./hardener audit` | Yes, safe | No |
| `./hardener apply` | **Stop bot first** | **Yes** |

### Why Stop the Bot?

1. **Gateway changes** (V01, V20, V23) - bind address and auth token are read at startup only
2. **Sandbox changes** (V03, V07, V11) - Docker settings cached on agent start
3. **Race conditions** - bot may overwrite config while hardener is editing
4. **File locks** - session/credential files may be locked by running process

### Recommended Workflow

```bash
# 1. Stop the gateway
moltbot gateway stop

# 2. Verify it's stopped
moltbot gateway status

# 3. Run hardener
./hardener audit                    # Check what needs fixing
./hardener apply                    # Apply fixes (interactive)
./hardener apply --yes              # Apply all fixes (auto)

# 4. Start the gateway
moltbot gateway start
```

### One-Liner

```bash
moltbot gateway stop && ./hardener apply --yes && moltbot gateway start
```

---

## Usage

### Scan for Vulnerabilities

```bash
./hardener audit                    # Basic scan
./hardener audit --json             # JSON output for CI/CD
./hardener audit --verbose          # Verbose output
./hardener list                     # List all available checks
```

### Apply Fixes

```bash
./hardener apply                    # Interactive (prompts for each fix)
./hardener apply --yes              # Auto-apply all fixes
./hardener apply --dry-run          # Show what would be fixed
./hardener apply --force            # Apply even if bot is running (not recommended)
```

### Fix Specific Vulnerability

```bash
./hardener fix V01                  # Fix single vulnerability
./hardener fix V03 --dry-run        # Preview fix
```

### Filter Checks

```bash
./hardener audit --skip V01,V02     # Skip specific checks
./hardener audit --only V03,V04     # Run only specific checks
```

### Reports

```bash
./hardener audit --json > report.json
./hardener check-deps
```

---

## Vulnerabilities Detected

| ID | Name | Severity | Auto-Fix |
|----|------|----------|----------|
| V01 | Gateway Exposure | Critical | Yes |
| V02 | DM Policy Open | Critical | Yes |
| V03 | Sandbox Disabled | Critical | Partial |
| V04 | Plaintext Credentials | Critical | Yes |
| V05 | Prompt Injection Surface | Critical | Partial |
| V06 | Dangerous Commands Enabled | Critical | Yes |
| V07 | No Network Isolation | High | Yes |
| V08 | Elevated Tool Access | Critical | Yes |
| V09 | No Audit Logging | Medium | Yes |
| V10 | Weak Pairing Codes | Medium | Yes |
| V11 | Unrestricted Bind Mounts | High | Yes |
| V12 | DNS Poisoning Risk | Medium | Yes |
| V13 | Shell Injection Vectors | Critical | Partial |
| V14 | DM Scope Context Leak | High | Yes |
| V15 | Pairing DoS | Medium | Yes |
| V16 | Browser Sandbox Escape | Critical | Yes |
| V17 | World-Readable Config | Critical | Yes |
| V18 | State Directory Exposure | Critical | Yes |
| V19 | Synced Folder Leak | High | Partial |
| V20 | Tailscale Funnel Exposure | Critical | Yes |
| V21 | Plugin Trust Boundary | High | Partial |
| V22 | Legacy Model Risk | High | Partial |
| V23 | Control UI Insecure Auth | Critical | Yes |
| V24 | Hooks Token Reuse | Medium | Yes |
| V25 | Group Policy Open | Critical | Yes |
| V26 | mDNS Information Disclosure | Medium | Yes |

See [docs/vulnerabilities/](docs/vulnerabilities/) for detailed documentation on each vulnerability.

### Partial Auto-Fix

Some vulnerabilities are marked **Partial** because automatic fixing could break your bot:

| ID | Why Partial | What Hardener Does |
|----|-------------|-------------------|
| V03 | Enabling sandbox may break custom bind mounts | Prompts for confirmation |
| V05 | Requires code changes in moltbot itself | Reports issue only |
| V13 | setupCommand may be legitimate | Warns, doesn't delete |
| V19 | Moving credentials could cause data loss | Warns, manual move |
| V21 | Unknown which plugins user needs | Asks which to allow |
| V22 | User's choice which AI model to use | Warns only |

Use `./hardener apply` (without `--yes`) to be prompted for each partial fix.

---

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/lubluniky/moltbot-hardener.git
cd moltbot-hardener
go build -o hardener ./cmd/hardener

# Run directly
./hardener audit

# Or install to PATH
sudo mv hardener /usr/local/bin/
```

### One-Liner Install

```bash
curl -fsSL https://raw.githubusercontent.com/lubluniky/moltbot-hardener/main/install-hardener.sh | bash
```

This installs to `~/.local/bin/hardener`. Make sure `~/.local/bin` is in your PATH.

### Using Go Install

```bash
go install github.com/lubluniky/moltbot-hardener/cmd/hardener@latest
```

---

## Bash Scripts

Standalone bash scripts are also included:

```bash
./scripts/full-audit.sh             # Full security audit
./scripts/harden-gateway.sh         # Harden gateway
./scripts/harden-sandbox.sh         # Harden sandbox
./scripts/secure-credentials.sh     # Secure credentials
./scripts/run-hardener.sh           # Interactive menu
```

---

## Integration with Moltbot

The hardener complements `moltbot security audit`:

```bash
# Built-in moltbot command
moltbot security audit

# Hardener (extended checks)
./hardener audit
./hardener apply
```

The hardener performs additional checks:
- Deeper filesystem permission analysis
- Cross-reference vulnerability chains
- Network exposure probing
- Firewall configuration

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / No critical findings |
| 1 | Error or critical findings present |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Add tests for new checks
4. Submit a pull request

### Adding New Checks

1. Create check function in `pkg/audit/checks.go`
2. Add documentation in `docs/vulnerabilities/V##-name.md`
3. Register in the scanner
4. Add tests in `pkg/audit/*_test.go`

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Built for [Moltbot](https://github.com/moltbot/moltbot). TUI powered by [bubbletea](https://github.com/charmbracelet/bubbletea).
