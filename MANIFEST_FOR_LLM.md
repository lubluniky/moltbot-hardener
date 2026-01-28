# Moltbot Security Hardening Manifest for AI Agents

This file is designed to be read by LLMs and AI coding agents (Claude, GPT, Cursor, etc.) to help users secure their Moltbot installation without breaking it.

**Total vulnerabilities documented: 70**

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

```bash
# Check if bot is running
moltbot gateway status

# Stop the bot (REQUIRED before fixes)
moltbot gateway stop

# Create backup
cp -r ~/.clawdbot ~/.clawdbot.backup
```

---

# PART 1: CONFIGURATION VULNERABILITIES (V01-V26)

These can be fixed via `moltbot config set` commands.

---

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

---

### V03: Sandbox Disabled (CRITICAL) ⚠️ ASK USER

**What:** Code execution runs without Docker isolation.

**Check:**
```bash
moltbot config get sandbox.mode
```

**Fix (ASK USER FIRST):**
```bash
moltbot config set sandbox.mode all
```

**Why ask:** May break custom bind mounts or setup commands.

---

### V04: Plaintext Credentials (CRITICAL)

**What:** API keys stored without encryption.

**Check:**
```bash
ls -la ~/.clawdbot/credentials/
grep -ri "key\|token\|secret" ~/.clawdbot/config.yaml
```

**Fix:**
```bash
moltbot config set credentials.encrypt true
```

---

### V05: Prompt Injection Surface (CRITICAL) ⚠️ MANUAL

**What:** Bot may execute malicious instructions from messages.

**Check:**
```bash
moltbot config get agent.systemPrompt
```

**Fix:** Cannot auto-fix. User must add injection guards to their prompt.

---

### V06: Dangerous Commands Enabled (CRITICAL)

**What:** Commands like `!shell` or `!eval` are enabled.

**Check:**
```bash
moltbot config get tools.shell.enabled
moltbot config get tools.eval.enabled
```

**Fix:**
```bash
moltbot config set tools.shell.enabled false
moltbot config set tools.eval.enabled false
```

---

### V07: No Network Isolation (HIGH)

**What:** Sandboxed containers have full network access.

**Check:**
```bash
moltbot config get sandbox.docker.network
```

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
```

**Fix:**
```bash
moltbot config set tools.permissions minimal
```

---

### V09: No Audit Logging (MEDIUM)

**What:** No log of who did what.

**Check:**
```bash
moltbot config get logging.audit
```

**Fix:**
```bash
moltbot config set logging.audit true
moltbot config set logging.file ~/.clawdbot/audit.log
```

---

### V10: Weak Pairing Codes (MEDIUM)

**What:** Pairing codes are too short or predictable.

**Check:**
```bash
moltbot config get pairing.codeLength
```

**Fix:**
```bash
moltbot config set pairing.codeLength 8
moltbot config set pairing.expiry 300
```

---

### V11: Unrestricted Bind Mounts (HIGH) ⚠️ ASK USER

**What:** Docker containers can access sensitive host paths.

**Check:**
```bash
moltbot config get sandbox.docker.bindMounts
```

Look for: `/`, `/etc`, `/root`, `/home`, `~/.ssh`, `~/.aws`, `/var/run/docker.sock`

**Fix:** User must manually remove dangerous mounts.

---

### V12: DNS Poisoning Risk (MEDIUM)

**What:** Container uses host DNS.

**Check:**
```bash
moltbot config get sandbox.docker.dns
```

**Fix:**
```bash
moltbot config set sandbox.docker.dns '["1.1.1.1", "8.8.8.8"]'
```

---

### V13: Shell Injection Vectors (CRITICAL) ⚠️ MANUAL

**What:** setupCommand may contain injection vulnerabilities.

**Check:**
```bash
moltbot config get sandbox.docker.setupCommand
```

Look for: `curl`, `wget`, `eval`, `bash -c`, `$()`, backticks

**Fix:** Report to user for manual review.

---

### V14: DM Scope Context Leak (HIGH)

**What:** Context from one DM leaks to another.

**Check:**
```bash
moltbot config get routing.dmScope
```

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
moltbot config get tools.browser.noSandbox
```

**Fix:**
```bash
moltbot config set tools.browser.sandbox true
moltbot config set tools.browser.noSandbox false
```

---

### V17: World-Readable Config (CRITICAL)

**What:** Config files readable by all users.

**Check:**
```bash
ls -la ~/.clawdbot/config.yaml
```

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
```

**Fix:**
```bash
chmod 700 ~/.clawdbot/
chmod 700 ~/.clawdbot/sessions/
```

---

### V19: Synced Folder Leak (HIGH) ⚠️ MANUAL

**What:** Credentials in cloud-synced folders.

**Check:** Look for `Dropbox`, `iCloud`, `OneDrive`, `Google Drive` in path.

**Fix:** User must move credentials manually.

---

### V20: Tailscale Funnel Exposure (CRITICAL)

**What:** Gateway exposed via Tailscale Funnel without auth.

**Check:**
```bash
moltbot config get gateway.tailscale.funnel
moltbot config get gateway.tailscale.auth
```

**Fix:**
```bash
moltbot config set gateway.tailscale.auth true
```

---

### V21: Plugin Trust Boundary (HIGH) ⚠️ ASK USER

**What:** Untrusted plugins can access sensitive data.

**Check:**
```bash
moltbot config get plugins.trusted
ls ~/.clawdbot/plugins/
```

**Fix:** User must specify trusted plugins.

---

### V22: Legacy Model Risk (HIGH) ⚠️ ASK USER

**What:** Using older AI models without safety features.

**Check:**
```bash
moltbot config get agent.model
```

**Fix:** User's preference - report only.

---

### V23: Control UI Insecure Auth (CRITICAL)

**What:** Web control UI has no authentication.

**Check:**
```bash
moltbot config get controlUI.auth
```

**Fix:**
```bash
moltbot config set controlUI.auth true
```

---

### V24: Hooks Token Reuse (MEDIUM)

**What:** Same token used for multiple hooks.

**Check:**
```bash
moltbot config get hooks
```

**Fix:** User must generate unique tokens.

---

### V25: Group Policy Open (CRITICAL)

**What:** Bot responds in any group without approval.

**Check:**
```bash
moltbot config get groupPolicy
```

**Fix:**
```bash
moltbot config set groupPolicy allowlist
```

---

### V26: mDNS Information Disclosure (MEDIUM)

**What:** Bot advertises itself on local network.

**Check:**
```bash
moltbot config get gateway.mdns
```

**Fix:**
```bash
moltbot config set gateway.mdns false
moltbot config set gateway.bonjour false
```

---

# PART 2: CODE-LEVEL VULNERABILITIES (V27-V50)

These require code review or are informational. Cannot be fixed via config alone.

---

## Authentication & Tokens

### V27: Timing Attack on Token Comparison (HIGH)

**What:** Token verification uses `===` instead of `crypto.timingSafeEqual()`. Allows timing attacks to guess tokens character by character.

**Location:** `src/infra/device-pairing.ts:396`, `src/infra/node-pairing.ts:271`

**Check:** Code review - look for `token === ` or `token !== ` comparisons.

**Fix:** Replace with `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.

---

### V28: Hook Token in Query Params (MEDIUM)

**What:** Hook tokens accepted via URL query parameters. Tokens in URLs get logged in access logs, browser history, referrer headers.

**Location:** `src/gateway/hooks.ts:59-60`

**Check:** Review webhook configurations for query param tokens.

**Fix:** Use Authorization header instead. Disable query param support.

---

### V29: OAuth Refresh Token Unencrypted (MEDIUM)

**What:** OAuth refresh tokens stored in plaintext JSON files.

**Location:** `src/agents/auth-profiles/store.ts`

**Check:**
```bash
cat ~/.clawdbot/auth-profiles.json
```

**Fix:** Use OS keychain (macOS Keychain, Linux Secret Service).

---

### V30: Session Key Spoofing (HIGH)

**What:** `/tools/invoke` endpoint accepts any `sessionKey` parameter without verifying ownership.

**Location:** `src/gateway/tools-invoke-http.ts:115-117`

**Check:** Test invoking tools with another user's session key.

**Fix:** Validate session ownership before allowing tool invocation.

---

### V31: WebSocket Handshake Replay (LOW)

**What:** Device signatures valid for 10 minutes, allowing replay attacks.

**Location:** `src/gateway/server/ws-connection/message-handler.ts:61`

**Check:** `DEVICE_SIGNATURE_SKEW_MS = 10 * 60 * 1000`

**Fix:** Reduce to 60-120 seconds. Add server-side nonce tracking.

---

## Plugin Security

### V32: Plugin Code No Verification (CRITICAL)

**What:** Plugins loaded via `jiti` without code signing, hash verification, or integrity checks.

**Location:** `src/plugins/loader.ts:294`

**Check:** Any installed plugin can execute arbitrary code.

**Fix:** Implement plugin signing mechanism. Verify checksums before loading.

---

### V33: NPM Supply Chain Attack (CRITICAL)

**What:** `npm install --omit=dev` runs lifecycle scripts (preinstall, postinstall) from untrusted packages.

**Location:** `src/plugins/install.ts:170`

**Check:** Plugin installation runs arbitrary npm scripts.

**Fix:** Use `--ignore-scripts` flag. Implement package allowlist.

---

### V34: Plugin Hook Injection (HIGH)

**What:** `before_tool_call` hook can modify any tool's parameters, including injecting malicious commands.

**Location:** `src/plugins/hooks.ts:284-298`

**Check:** Malicious plugin can intercept and modify bash commands, web requests, etc.

**Fix:** Implement parameter change auditing. Restrict which plugins can use this hook.

---

### V35: Plugin Allowlist Not Enforced (HIGH)

**What:** `plugins.allow` config only triggers a warning in audit, doesn't actually block loading.

**Location:** `src/plugins/loader.ts:252-276`

**Check:**
```bash
moltbot config get plugins.allow
# Even if set, unlisted plugins still load
```

**Fix:** Enforce allowlist at load time, not just audit.

---

### V36: Plugin Runtime Exposes Dangerous API (HIGH)

**What:** Plugin runtime gives access to `writeConfigFile`, `runCommandWithTimeout`, channel send functions.

**Location:** `src/plugins/runtime/index.ts:165-357`

**Check:** Any plugin can modify core config or execute commands.

**Fix:** Implement capability-based permissions for runtime API.

---

### V37: Plugin HTTP Route Hijacking (MEDIUM)

**What:** Plugins can register HTTP routes without path restrictions, potentially shadowing gateway routes.

**Location:** `src/plugins/registry.ts:294-324`

**Check:** Plugin could register `/api/...` routes.

**Fix:** Enforce routes under `/plugins/<pluginId>/...` prefix.

---

### V38: Plugin CLI Command Injection (MEDIUM)

**What:** Plugins get full Commander.js program object, can shadow core commands.

**Location:** `src/plugins/registry.ts:383-396`

**Check:** Plugin could override `moltbot config` command.

**Fix:** Pass scoped subcommand, not full program.

---

## Network Security

### V39: No WebSocket Rate Limiting (MEDIUM)

**What:** No limit on WebSocket connections per IP. Can exhaust server resources.

**Location:** `src/gateway/server-runtime-state.ts`

**Check:** No `rateLimit` or `maxConnections` configuration found.

**Fix:** Add per-IP connection rate limiting.

---

### V40: No HTTP Request Timeout (MEDIUM)

**What:** HTTP server doesn't configure timeouts. Vulnerable to slowloris attacks.

**Location:** `src/gateway/server-http.ts`

**Check:** No `headersTimeout`, `requestTimeout`, `keepAliveTimeout` set.

**Fix:**
```javascript
httpServer.headersTimeout = 60_000;
httpServer.requestTimeout = 300_000;
```

---

### V41: WebSocket Origin Not Validated (MEDIUM)

**What:** Origin header extracted but not validated. Allows cross-origin WebSocket CSRF.

**Location:** `src/gateway/server/ws-connection.ts:73`

**Check:** No `verifyClient` callback in WebSocket server.

**Fix:** Add origin allowlist validation.

---

### V42: SSRF Redirect Bypass (MEDIUM)

**What:** SSRF protection validates initial URL but redirect targets may bypass checks.

**Location:** `src/media/input-files.ts:173-184`

**Check:** Redirect to `http://169.254.169.254` (AWS metadata) may succeed.

**Fix:** Re-validate each redirect target against SSRF rules.

---

### V43: Proxy Header Trust Issues (MEDIUM)

**What:** Proxy headers trusted without strict IP validation.

**Location:** `src/gateway/auth.ts:68-104`

**Check:** X-Forwarded-For can be spoofed if attacker bypasses proxy.

**Fix:** Use canonical IP address comparison. Validate proxy chain.

---

## Filesystem Security

### V44: Log Directory World-Readable (MEDIUM)

**What:** Logs written to `/tmp/moltbot` which is world-readable.

**Location:** `src/logging/logger.ts:15-16`

**Check:**
```bash
ls -la /tmp/moltbot/
```

**Fix:** Store logs in `~/.clawdbot/logs/` with 0600 permissions.

---

### V45: Session Transcript Path Injection (MEDIUM)

**What:** `topicId` parameter used in file paths without full sanitization.

**Location:** `src/config/sessions/paths.ts:41-49`

**Check:** Test with `topicId = "..%2F..%2Fetc%2Fpasswd"`

**Fix:** Validate resolved path stays within expected directory.

---

### V46: Gateway Lock File Predictable (MEDIUM)

**What:** Lock file in `/tmp/moltbot-<uid>` allows local DoS by pre-creating directory.

**Location:** `src/config/paths.ts:175-180`

**Check:** Another user can block gateway start.

**Fix:** Use `~/.clawdbot/` for lock files.

---

### V47: Config Backup Exposes Old Secrets (LOW)

**What:** Config backups (`.bak.1` through `.bak.4`) may contain rotated API keys.

**Location:** `src/config/io.ts:91-106`

**Check:**
```bash
ls ~/.clawdbot/config.yaml.bak*
```

**Fix:** Encrypt backups or reduce retention.

---

### V48: Plugin Archive Zip Bomb (MEDIUM)

**What:** Plugin archive extraction has no size limit. Zip bomb can fill disk.

**Location:** `src/plugins/install.ts`, `src/infra/archive.ts`

**Check:** Install a compressed archive that expands to GB.

**Fix:** Track decompressed size, abort if threshold exceeded.

---

## Message Handling

### V49: Session Key Collision via Normalization (MEDIUM)

**What:** Invalid characters normalized to hyphens, causing collisions. `foo_bar` and `foo@bar` → `foo-bar`.

**Location:** `src/routing/session-key.ts:57-98`

**Check:** Two different users may share session state.

**Fix:** Use collision-resistant normalization (base64) or reject invalid chars.

---

### V50: Unicode Bypass in Allowlists (MEDIUM)

**What:** Username allowlist comparison doesn't account for Unicode confusables.

**Location:** `src/telegram/bot-access.ts`, `src/discord/monitor/allow-list.ts`

**Check:** Cyrillic 'а' vs Latin 'a' bypasses allowlist.

**Fix:** Apply Unicode NFC normalization before comparison.

---

# PART 3: ADVANCED VULNERABILITIES (V51-V70)

---

### V51: SCP Command Injection (HIGH)

**What:** Remote host/path for SCP constructed without shell escaping.

**Location:** `src/auto-reply/reply/stage-sandbox-media.ts:132-159`

**Check:** `remoteHost = "host; rm -rf /"` → RCE

**Fix:** Use proper shell escaping or spawn with array args.

---

### V52: Forwarded Message Spoofing (MEDIUM)

**What:** Discord forwarded message author from untrusted snapshot data.

**Location:** `src/discord/monitor/message-utils.ts:211-226`

**Check:** Forged author attribution in forwarded content.

**Fix:** Sanitize snapshot author fields. Mark as untrusted.

---

### V53: Media Filename Path Traversal (LOW)

**What:** Content-Disposition filename may contain traversal sequences.

**Location:** `src/media/fetch.ts:36-51`

**Check:** `filename*=UTF-8''..%2F..%2Fetc%2Fpasswd`

**Fix:** Apply `sanitizeFilename()` consistently.

---

### V54: Unbounded History Memory (MEDIUM)

**What:** Group chat history maps grow unboundedly across channels.

**Location:** `src/auto-reply/reply/history.ts`

**Check:** Memory exhaustion with many channels.

**Fix:** Implement LRU eviction. Set max tracked channels.

---

### V55: Sticker Cache No Size Limit (LOW)

**What:** Telegram sticker cache grows without bounds.

**Location:** `src/telegram/sticker-cache.ts`

**Check:**
```bash
wc -c ~/.clawdbot/telegram/sticker-cache.json
```

**Fix:** Add LRU eviction policy.

---

### V56: Telegram Link Injection (LOW)

**What:** Links may contain `javascript:` protocol.

**Location:** `src/telegram/format.ts:23-34`

**Check:** Send `javascript:alert(1)` link.

**Fix:** Validate links start with `http://` or `https://`.

---

### V57: Slack Mrkdwn Token Bypass (LOW)

**What:** Allowlist check only validates prefix, not full token.

**Location:** `src/slack/format.ts:13-26`

**Check:** `<@|malicious>` bypasses check.

**Fix:** Validate complete token structure with strict regex.

---

### V58: Thread ID Integer Overflow (LOW)

**What:** Large thread IDs may overflow 32-bit integers.

**Location:** `src/channels/plugins/outbound/telegram.ts:11-20`

**Check:** Send extremely large thread ID.

**Fix:** Validate within safe integer bounds.

---

### V59: No Rate Limit on Pairing Generation (MEDIUM)

**What:** Can generate unlimited pairing codes by sending from different IDs.

**Location:** `src/telegram/pairing-store.ts`

**Check:** Rapid pairing requests from multiple senders.

**Fix:** Implement rate limiting. Limit total pending requests.

---

### V60: Regex ReDoS in Mentions (LOW)

**What:** User-provided mention patterns compiled to regex without validation.

**Location:** `src/auto-reply/reply/mentions.ts`

**Check:** Pattern `(a+)+b` with string of 'a's.

**Fix:** Validate patterns against ReDoS. Add timeout wrapper.

---

### V61: Thread Starter Context Leak (LOW)

**What:** Thread starter cache may serve stale data across sessions.

**Location:** `src/slack/monitor/message-handler/prepare.ts:454-491`

**Check:** Thread context leaks between sessions.

**Fix:** Include session key in cache key.

---

### V62: DNS Rebinding via SSRF (MEDIUM)

**What:** DNS re-resolution may return different IP after initial check.

**Location:** `src/infra/net/ssrf.ts`

**Check:** DNS rebinding attack server.

**Fix:** Pin DNS across redirect chains. Re-validate on each connection.

---

### V63: mDNS Exposes Internal Ports (LOW)

**What:** Bonjour advertises gatewayPort, sshPort, cliPath, canvasPort.

**Location:** `src/infra/bonjour.ts:105-148`

**Check:** mDNS scan reveals internal configuration.

**Fix:** Enable minimal mode by default. Remove sensitive fields.

---

### V64: Self-Signed Cert Weak Key (LOW)

**What:** Self-signed certificates use RSA 2048-bit.

**Location:** `src/infra/tls/gateway.ts:49`

**Check:** `-newkey rsa:2048`

**Fix:** Use `rsa:4096` or ECDSA P-384.

---

### V65: Control UI Auth Bypass Config (LOW)

**What:** `allowInsecureAuth` and `dangerouslyDisableDeviceAuth` options exist.

**Location:** `src/gateway/server/ws-connection/message-handler.ts:371-376`

**Check:** These flags weaken security when enabled.

**Fix:** Add warning logs. Require explicit confirmation.

---

### V66: Pairing Code Brute Force (LOW)

**What:** No rate limiting on code verification attempts.

**Location:** `src/pairing/pairing-store.ts`

**Check:** 10^12 combinations but no attempt limiting.

**Fix:** Rate limit verification. Exponential backoff after failures.

---

### V67: API Key in Error Messages (LOW)

**What:** OAuth errors may expose credential fragments in logs.

**Location:** `src/agents/auth-profiles/oauth.ts:225-236`

**Check:** Review error handling for credential exposure.

**Fix:** Sanitize error messages before logging.

---

### V68: WebSocket Buffer Overflow (LOW)

**What:** Slow clients accumulate unbounded message buffers.

**Location:** `src/gateway/server-constants.ts:2`

**Check:** Memory growth with slow clients.

**Fix:** Implement strict per-connection limits with message dropping.

---

### V69: Device Auth Store Unencrypted (LOW)

**What:** Device tokens stored in plaintext JSON.

**Location:** `src/infra/device-auth-store.ts`

**Check:**
```bash
cat ~/.clawdbot/identity/device-auth.json
```

**Fix:** Encrypt at rest or use OS keychain.

---

### V70: Exec Approvals Token Cleartext (MEDIUM)

**What:** Exec approval socket token stored in cleartext.

**Location:** `src/infra/exec-approvals.ts:170-173`

**Check:**
```bash
cat ~/.clawdbot/exec-approvals.json | jq '.socket.token'
```

**Fix:** Use OS keychain. Implement token rotation.

---

# QUICK REFERENCE

## Safe Auto-Fix Commands

```bash
#!/bin/bash
# Run after: moltbot gateway stop

# Gateway
moltbot config set gateway.bind loopback
moltbot config set gateway.mdns false
moltbot config set gateway.bonjour false

# Policies
moltbot config set dmPolicy pairing
moltbot config set groupPolicy allowlist

# Sandbox
moltbot config set sandbox.docker.network none
moltbot config set sandbox.docker.dns '["1.1.1.1", "8.8.8.8"]'

# Tools
moltbot config set tools.shell.enabled false
moltbot config set tools.eval.enabled false
moltbot config set tools.browser.sandbox true
moltbot config set tools.browser.noSandbox false
moltbot config set tools.permissions minimal

# Auth
moltbot config set controlUI.auth true
moltbot config set gateway.tailscale.auth true

# Logging
moltbot config set logging.audit true
moltbot config set logging.file ~/.clawdbot/audit.log

# Pairing
moltbot config set pairing.codeLength 8
moltbot config set pairing.expiry 300
moltbot config set pairing.rateLimit 5
moltbot config set pairing.maxAttempts 3

# Session
moltbot config set routing.dmScope per-user

# File permissions
chmod 700 ~/.clawdbot/
chmod 600 ~/.clawdbot/config.yaml
chmod 700 ~/.clawdbot/credentials/ 2>/dev/null
chmod 600 ~/.clawdbot/credentials/* 2>/dev/null
chmod 700 ~/.clawdbot/sessions/ 2>/dev/null

echo "Done. Run: moltbot gateway start"
```

## What NOT to Auto-Fix (Ask User)

| ID | Why |
|----|-----|
| V03 | Sandbox may break custom workflows |
| V05 | Requires prompt review |
| V11 | User may need specific mounts |
| V13 | setupCommand may be legitimate |
| V19 | User must move files manually |
| V21 | User chooses trusted plugins |
| V22 | User's model preference |
| V24 | User must generate new tokens |

## Severity Summary

| Severity | Config (V01-V26) | Code (V27-V70) | Total |
|----------|------------------|----------------|-------|
| CRITICAL | 12 | 4 | 16 |
| HIGH | 5 | 8 | 13 |
| MEDIUM | 6 | 19 | 25 |
| LOW | 3 | 13 | 16 |
| **Total** | **26** | **44** | **70** |

---

*This manifest is part of [moltbot-hardener](https://github.com/lubluniky/moltbot-hardener)*
