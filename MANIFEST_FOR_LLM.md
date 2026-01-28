# Moltbot Security Hardening Manifest for AI Agents

This file is designed to be read by LLMs and AI coding agents (Claude, GPT, Cursor, etc.) to help users secure their Moltbot installation without breaking it.

---

## CRITICAL SAFETY RULES

**READ THIS FIRST. DO NOT SKIP.**

1. **NEVER modify config while the bot is running** - Changes won't apply and may cause race conditions
2. **ALWAYS stop the gateway first**: `moltbot gateway stop`
3. **ALWAYS restart after changes**: `moltbot gateway start`
4. **NEVER delete credential files** - User will lose access to channels
5. **NEVER change sandbox settings without asking** - May break user's workflows
6. **BACKUP before making changes**: `cp -r ~/.clawdbot ~/.clawdbot.backup`
7. **Test after each fix** - Run `moltbot channels status` to verify bot still works

---

## BEFORE YOU START

### Check if bot is running
```bash
moltbot gateway status
```

### Stop the bot (REQUIRED before fixes)
```bash
moltbot gateway stop
```

### Create backup
```bash
cp -r ~/.clawdbot ~/.clawdbot.backup
```

---

## VULNERABILITIES CHECKLIST

### V01: Gateway Exposure (CRITICAL)

**What:** Gateway bound to 0.0.0.0 exposes it to the entire network.

**Check:**
```bash
moltbot config get gateway.bind
```
- BAD: `0.0.0.0` or empty
- GOOD: `127.0.0.1` or `loopback`

**Fix:**
```bash
moltbot config set gateway.bind loopback
```

**Verify:**
```bash
moltbot config get gateway.bind
# Should return: loopback
```

---

### V02: DM Policy Open (CRITICAL)

**What:** Anyone can DM the bot without pairing/approval.

**Check:**
```bash
moltbot config get dmPolicy
```
- BAD: `open` or empty
- GOOD: `pairing` or `allowlist`

**Fix:**
```bash
moltbot config set dmPolicy pairing
```

**Note:** `pairing` requires users to enter a code. `allowlist` is stricter (manual approval).

---

### V03: Sandbox Disabled (CRITICAL) ⚠️ PARTIAL

**What:** Code execution runs without Docker isolation.

**Check:**
```bash
moltbot config get sandbox.mode
```
- BAD: `off` or `none` or empty
- GOOD: `all`

**Fix (ASK USER FIRST):**
```bash
# WARNING: This may break custom workflows!
moltbot config set sandbox.mode all
```

**Why ask:** User may have bind mounts or setup commands that require sandbox to be off.

---

### V04: Plaintext Credentials (CRITICAL)

**What:** API keys stored without encryption.

**Check:**
```bash
ls -la ~/.clawdbot/credentials/
cat ~/.clawdbot/config.yaml | grep -i "key\|token\|secret"
```

Look for plaintext API keys in config files.

**Fix:**
```bash
# Move to secure credential store
moltbot config set credentials.encrypt true
```

**Alternative:** Use environment variables instead of config file.

---

### V05: Prompt Injection Surface (CRITICAL) ⚠️ PARTIAL

**What:** Bot may execute malicious instructions from messages.

**Check:**
```bash
moltbot config get agent.systemPrompt
```

Look for lack of injection guards.

**Fix:** This requires code/prompt changes. Report to user:
- Add instruction boundaries in system prompt
- Use `{{USER_INPUT}}` markers
- Consider input sanitization

**Cannot auto-fix** - requires user's custom prompt review.

---

### V06: Dangerous Commands Enabled (CRITICAL)

**What:** Commands like `!shell` or `!eval` are enabled.

**Check:**
```bash
moltbot config get commands.dangerous
moltbot config get tools.shell.enabled
moltbot config get tools.eval.enabled
```

**Fix:**
```bash
moltbot config set tools.shell.enabled false
moltbot config set tools.eval.enabled false
moltbot config set commands.dangerous false
```

---

### V07: No Network Isolation (HIGH)

**What:** Sandboxed containers have full network access.

**Check:**
```bash
moltbot config get sandbox.docker.network
```
- BAD: `bridge` or `host` or empty
- GOOD: `none`

**Fix:**
```bash
moltbot config set sandbox.docker.network none
```

---

### V08: Elevated Tool Access (CRITICAL)

**What:** Tools have more permissions than needed.

**Check:**
```bash
moltbot config get tools.permissions
moltbot config get agent.tools
```

Look for `*` (all tools) or dangerous tools enabled by default.

**Fix:**
```bash
# Set minimal tool set
moltbot config set tools.permissions minimal
```

---

### V09: No Audit Logging (MEDIUM)

**What:** No log of who did what.

**Check:**
```bash
moltbot config get logging.file
moltbot config get logging.audit
```
- BAD: empty or `false`
- GOOD: path to log file

**Fix:**
```bash
moltbot config set logging.file ~/.clawdbot/audit.log
moltbot config set logging.audit true
```

---

### V10: Weak Pairing Codes (MEDIUM)

**What:** Pairing codes are too short or predictable.

**Check:**
```bash
moltbot config get pairing.codeLength
moltbot config get pairing.expiry
```
- BAD: codeLength < 6, expiry > 3600
- GOOD: codeLength >= 8, expiry <= 300

**Fix:**
```bash
moltbot config set pairing.codeLength 8
moltbot config set pairing.expiry 300
```

---

### V11: Unrestricted Bind Mounts (HIGH)

**What:** Docker containers can access sensitive host paths.

**Check:**
```bash
moltbot config get sandbox.docker.bindMounts
```

Look for dangerous paths: `/`, `/etc`, `/root`, `/home`, `~/.ssh`, `~/.aws`, `/var/run/docker.sock`

**Fix (ASK USER FIRST):**
```bash
# Remove dangerous bind mounts - user must specify safe paths
moltbot config set sandbox.docker.bindMounts '[]'
```

---

### V12: DNS Poisoning Risk (MEDIUM)

**What:** Container uses host DNS, vulnerable to poisoning.

**Check:**
```bash
moltbot config get sandbox.docker.dns
```

**Fix:**
```bash
moltbot config set sandbox.docker.dns '["1.1.1.1", "8.8.8.8"]'
```

---

### V13: Shell Injection Vectors (CRITICAL) ⚠️ PARTIAL

**What:** setupCommand may contain injection vulnerabilities.

**Check:**
```bash
moltbot config get sandbox.docker.setupCommand
```

Look for: `curl`, `wget`, `eval`, `bash -c`, `sh -c`, `$()`, backticks

**Fix:** Cannot auto-fix. Report dangerous patterns to user for review.

---

### V14: DM Scope Context Leak (HIGH)

**What:** Context from one DM conversation leaks to another.

**Check:**
```bash
moltbot config get agent.sessionScope
moltbot config get routing.dmScope
```
- BAD: `global` or empty
- GOOD: `per-user` or `per-channel`

**Fix:**
```bash
moltbot config set routing.dmScope per-user
```

---

### V15: Pairing DoS (MEDIUM)

**What:** No rate limiting on pairing attempts.

**Check:**
```bash
moltbot config get pairing.rateLimit
moltbot config get pairing.maxAttempts
```

**Fix:**
```bash
moltbot config set pairing.rateLimit 5
moltbot config set pairing.maxAttempts 3
```

---

### V16: Browser Sandbox Escape (CRITICAL)

**What:** Browser automation can escape sandbox.

**Check:**
```bash
moltbot config get tools.browser.sandbox
moltbot config get tools.browser.noSandbox
```
- BAD: `noSandbox: true`
- GOOD: `sandbox: true`

**Fix:**
```bash
moltbot config set tools.browser.sandbox true
moltbot config set tools.browser.noSandbox false
```

---

### V17: World-Readable Config (CRITICAL)

**What:** Config files readable by all users on system.

**Check:**
```bash
ls -la ~/.clawdbot/config.yaml
ls -la ~/.clawdbot/credentials/
```
- BAD: `-rw-r--r--` (644) or worse
- GOOD: `-rw-------` (600)

**Fix:**
```bash
chmod 600 ~/.clawdbot/config.yaml
chmod 700 ~/.clawdbot/credentials/
chmod 600 ~/.clawdbot/credentials/*
```

---

### V18: State Directory Exposure (CRITICAL)

**What:** State directory has wrong permissions.

**Check:**
```bash
ls -la ~/.clawdbot/
ls -la ~/.clawdbot/sessions/
```

**Fix:**
```bash
chmod 700 ~/.clawdbot/
chmod 700 ~/.clawdbot/sessions/
```

---

### V19: Synced Folder Leak (HIGH) ⚠️ PARTIAL

**What:** Credentials in cloud-synced folders (Dropbox, iCloud, etc.)

**Check:**
```bash
# Check if .clawdbot is in synced location
echo ~/.clawdbot
# Check for symlinks to cloud folders
ls -la ~/.clawdbot
```

Look for paths containing: `Dropbox`, `iCloud`, `OneDrive`, `Google Drive`

**Fix:** Cannot auto-fix. User must move credentials manually:
```bash
# Example (user must adjust paths)
mv ~/.clawdbot ~/secure-location/.clawdbot
ln -s ~/secure-location/.clawdbot ~/.clawdbot
```

---

### V20: Tailscale Funnel Exposure (CRITICAL)

**What:** Gateway exposed via Tailscale Funnel without auth.

**Check:**
```bash
moltbot config get gateway.tailscale.funnel
moltbot config get gateway.tailscale.auth
```
- BAD: `funnel: true` without `auth: true`
- GOOD: `funnel: false` or `funnel: true` with `auth: true`

**Fix:**
```bash
moltbot config set gateway.tailscale.auth true
# Or disable funnel entirely:
moltbot config set gateway.tailscale.funnel false
```

---

### V21: Plugin Trust Boundary (HIGH) ⚠️ PARTIAL

**What:** Untrusted plugins can access sensitive data.

**Check:**
```bash
moltbot config get plugins.enabled
moltbot config get plugins.trusted
ls ~/.clawdbot/plugins/
```

**Fix:** Cannot auto-fix. Ask user which plugins they need:
```bash
# Example - user must specify
moltbot config set plugins.trusted '["official-plugin-1", "official-plugin-2"]'
```

---

### V22: Legacy Model Risk (HIGH) ⚠️ PARTIAL

**What:** Using older AI models without safety features.

**Check:**
```bash
moltbot config get agent.model
moltbot config get agent.provider
```

Look for deprecated models: `gpt-3.5-turbo`, `claude-instant`, old dated versions

**Fix:** Report to user. Model choice is their preference.

---

### V23: Control UI Insecure Auth (CRITICAL)

**What:** Web control UI has no authentication.

**Check:**
```bash
moltbot config get controlUI.auth
moltbot config get controlUI.enabled
```
- BAD: `auth: false` or empty when `enabled: true`
- GOOD: `auth: true` or `enabled: false`

**Fix:**
```bash
moltbot config set controlUI.auth true
# Or disable if not needed:
moltbot config set controlUI.enabled false
```

---

### V24: Hooks Token Reuse (MEDIUM)

**What:** Same token used for multiple hooks.

**Check:**
```bash
moltbot config get hooks
```

Look for duplicate `token` values across different hooks.

**Fix:**
```bash
# Generate unique tokens for each hook
# User must update their hook configurations
```

---

### V25: Group Policy Open (CRITICAL)

**What:** Bot responds in any group without approval.

**Check:**
```bash
moltbot config get groupPolicy
```
- BAD: `open` or empty
- GOOD: `allowlist` or `disabled`

**Fix:**
```bash
moltbot config set groupPolicy allowlist
```

---

### V26: mDNS Information Disclosure (MEDIUM)

**What:** Bot advertises itself on local network via mDNS.

**Check:**
```bash
moltbot config get gateway.mdns
moltbot config get gateway.bonjour
```
- BAD: `true`
- GOOD: `false`

**Fix:**
```bash
moltbot config set gateway.mdns false
moltbot config set gateway.bonjour false
```

---

## AFTER FIXING

### Restart the gateway
```bash
moltbot gateway start
```

### Verify bot works
```bash
moltbot gateway status
moltbot channels status
```

### Run audit again
```bash
# If hardener is installed:
./hardener audit

# Or built-in:
moltbot security audit
```

---

## QUICK FIX SCRIPT

If user wants to apply all safe fixes at once, run this (AFTER stopping bot):

```bash
#!/bin/bash
# Safe fixes only - won't break anything

moltbot config set gateway.bind loopback
moltbot config set dmPolicy pairing
moltbot config set groupPolicy allowlist
moltbot config set sandbox.docker.network none
moltbot config set tools.shell.enabled false
moltbot config set tools.eval.enabled false
moltbot config set logging.audit true
moltbot config set logging.file ~/.clawdbot/audit.log
moltbot config set pairing.codeLength 8
moltbot config set pairing.expiry 300
moltbot config set tools.browser.sandbox true
moltbot config set gateway.mdns false
moltbot config set controlUI.auth true

# File permissions
chmod 700 ~/.clawdbot/
chmod 600 ~/.clawdbot/config.yaml
chmod 700 ~/.clawdbot/credentials/ 2>/dev/null
chmod 600 ~/.clawdbot/credentials/* 2>/dev/null
chmod 700 ~/.clawdbot/sessions/ 2>/dev/null

echo "Safe fixes applied. Run: moltbot gateway start"
```

---

## WHAT NOT TO DO

1. **DO NOT** run `moltbot config set sandbox.mode all` without asking - breaks custom workflows
2. **DO NOT** delete any files in `~/.clawdbot/` - contains sessions and credentials
3. **DO NOT** change `bindMounts` without asking - user may need specific mounts
4. **DO NOT** modify running bot config - always stop first
5. **DO NOT** disable channels without asking - user loses messaging access
6. **DO NOT** change model/provider without asking - user's preference
7. **DO NOT** remove plugins without asking - user may need them

---

## SUMMARY TABLE

| ID | Name | Safe to Auto-Fix? | Command |
|----|------|-------------------|---------|
| V01 | Gateway Exposure | YES | `moltbot config set gateway.bind loopback` |
| V02 | DM Policy Open | YES | `moltbot config set dmPolicy pairing` |
| V03 | Sandbox Disabled | NO - ASK | `moltbot config set sandbox.mode all` |
| V04 | Plaintext Credentials | YES | `moltbot config set credentials.encrypt true` |
| V05 | Prompt Injection | NO - MANUAL | Report only |
| V06 | Dangerous Commands | YES | `moltbot config set tools.shell.enabled false` |
| V07 | No Network Isolation | YES | `moltbot config set sandbox.docker.network none` |
| V08 | Elevated Tool Access | YES | `moltbot config set tools.permissions minimal` |
| V09 | No Audit Logging | YES | `moltbot config set logging.audit true` |
| V10 | Weak Pairing Codes | YES | `moltbot config set pairing.codeLength 8` |
| V11 | Unrestricted Bind Mounts | NO - ASK | Review mounts manually |
| V12 | DNS Poisoning Risk | YES | `moltbot config set sandbox.docker.dns '["1.1.1.1"]'` |
| V13 | Shell Injection | NO - MANUAL | Report only |
| V14 | DM Scope Context Leak | YES | `moltbot config set routing.dmScope per-user` |
| V15 | Pairing DoS | YES | `moltbot config set pairing.rateLimit 5` |
| V16 | Browser Sandbox Escape | YES | `moltbot config set tools.browser.sandbox true` |
| V17 | World-Readable Config | YES | `chmod 600 ~/.clawdbot/config.yaml` |
| V18 | State Directory Exposure | YES | `chmod 700 ~/.clawdbot/` |
| V19 | Synced Folder Leak | NO - MANUAL | User must move files |
| V20 | Tailscale Funnel | YES | `moltbot config set gateway.tailscale.auth true` |
| V21 | Plugin Trust | NO - ASK | User specifies trusted plugins |
| V22 | Legacy Model Risk | NO - ASK | User's preference |
| V23 | Control UI Auth | YES | `moltbot config set controlUI.auth true` |
| V24 | Hooks Token Reuse | NO - MANUAL | Generate unique tokens |
| V25 | Group Policy Open | YES | `moltbot config set groupPolicy allowlist` |
| V26 | mDNS Disclosure | YES | `moltbot config set gateway.mdns false` |

---

*This manifest is part of [moltbot-hardener](https://github.com/lubluniky/moltbot-hardener)*
