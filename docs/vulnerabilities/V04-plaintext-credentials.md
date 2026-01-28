# V04: Plaintext Credentials

## Overview

| Property | Value |
|----------|-------|
| **ID** | V04 |
| **Severity** | Critical |
| **Category** | Filesystem |
| **Auto-Fix** | Yes |
| **CVSS Score** | 8.2 |

## Description

Sensitive credentials (API keys, tokens, passwords) are stored in plaintext in configuration files with overly permissive file permissions. This allows:

- Other users on the system to read credentials
- Malicious processes to harvest secrets
- Backup systems to capture unencrypted secrets
- Cloud sync services to propagate credentials

## Affected Files in Moltbot

- `~/.moltbot/moltbot.json` - Main config (may contain tokens)
- `~/.moltbot/credentials/*.json` - Channel credentials
- `~/.moltbot/agents/*/agent/auth-profiles.json` - API keys and OAuth tokens
- `src/config/paths.ts` - Credential path resolution
- `src/security/audit-fs.ts` - Permission checking

## Attack Scenario

1. **Local Access**: Attacker gains limited shell access or has account on shared system
2. **Discovery**: Finds moltbot config with world/group readable permissions
3. **Extraction**: Reads API keys, tokens, credentials
4. **Exploitation**:
   - Uses API keys for unauthorized access
   - Impersonates the bot on messaging platforms
   - Accesses cloud services
   - Exfiltrates via billing APIs

### Attack Vector

```
Local Access -> Read Config -> Extract Credentials -> Abuse Services
```

### Example Attack

```bash
# Attacker on shared system
$ ls -la /home/victim/.moltbot/
drwxr-xr-x  victim  staff  .moltbot
-rw-r--r--  victim  staff  moltbot.json  # World readable!

$ cat /home/victim/.moltbot/moltbot.json | jq '.gateway.auth.token'
"sk-secret-gateway-token-here"

$ cat /home/victim/.moltbot/agents/main/agent/auth-profiles.json
{
  "anthropic": {"key": "sk-ant-api-key-here"},
  "openai": {"key": "sk-openai-key-here"}
}
```

## Detection

```go
func (c *PlaintextCredsCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    paths := []string{
        ctx.ConfigPath,
        filepath.Join(ctx.StateDir, "credentials"),
        filepath.Join(ctx.StateDir, "agents"),
    }

    for _, p := range paths {
        perms, err := inspectPermissions(p)
        if err != nil {
            continue
        }

        if perms.WorldReadable || perms.GroupReadable {
            findings = append(findings, Finding{
                CheckID:      "V04",
                Severity:     SeverityCritical,
                Title:        "Credentials readable by others",
                AffectedPath: p,
            })
        }
    }

    return findings, nil
}
```

## Fix Applied by Hardener

The hardener tightens file permissions:

```bash
# Directories: 700 (owner only)
chmod 700 ~/.moltbot
chmod 700 ~/.moltbot/credentials
chmod 700 ~/.moltbot/agents/*/agent
chmod 700 ~/.moltbot/agents/*/sessions

# Files: 600 (owner read/write only)
chmod 600 ~/.moltbot/moltbot.json
chmod 600 ~/.moltbot/credentials/*.json
chmod 600 ~/.moltbot/agents/*/agent/auth-profiles.json
chmod 600 ~/.moltbot/agents/*/sessions/sessions.json
```

## Manual Fix Instructions

### Fix Permissions

```bash
# Run the built-in fix
moltbot security audit --fix

# Or manually
chmod 700 ~/.moltbot
chmod 600 ~/.moltbot/moltbot.json
find ~/.moltbot/credentials -type f -name "*.json" -exec chmod 600 {} \;
find ~/.moltbot/agents -type f -name "*.json" -exec chmod 600 {} \;
```

### Move Secrets to Environment Variables

```bash
# Instead of storing in config:
# "gateway": { "auth": { "token": "secret" } }

# Use environment variable:
export CLAWDBOT_GATEWAY_TOKEN="your-secret-token"

# Reference in config:
# "gateway": { "auth": { "token": "${CLAWDBOT_GATEWAY_TOKEN}" } }
```

### Use macOS Keychain (if available)

```bash
# Store API key in keychain
security add-generic-password -a moltbot -s anthropic-api-key -w "sk-ant-..."

# Retrieve in scripts
security find-generic-password -a moltbot -s anthropic-api-key -w
```

## Verification Steps

1. **Check config permissions**:
   ```bash
   ls -la ~/.moltbot/moltbot.json
   # Should show: -rw------- (600)
   ```

2. **Check state directory**:
   ```bash
   ls -la ~/.moltbot/
   # Should show: drwx------ (700)
   ```

3. **Check credentials directory**:
   ```bash
   ls -la ~/.moltbot/credentials/
   # All files should be 600
   ```

4. **Run security audit**:
   ```bash
   moltbot security audit
   # Should not show permission warnings
   ```

5. **Test as another user**:
   ```bash
   sudo -u nobody cat ~/.moltbot/moltbot.json
   # Should fail with permission denied
   ```

## Windows Considerations

On Windows, the hardener uses `icacls`:

```powershell
# Remove inheritance and set owner-only access
icacls "%USERPROFILE%\.moltbot" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
```

## Related Vulnerabilities

- [V17: World-Readable Config](V17-world-readable-config.md)
- [V18: State Directory Exposure](V18-state-dir-exposure.md)
- [V19: Synced Folder Leak](V19-synced-folder-leak.md)

## References

- [Moltbot Security - Secrets on Disk](https://docs.molt.bot/gateway/security#secrets-on-disk)
- [Credential Storage Map](https://docs.molt.bot/gateway/security#credential-storage-map)
