# V17: World-Readable Config

## Overview

| Property | Value |
|----------|-------|
| **ID** | V17 |
| **Severity** | Critical |
| **Category** | Filesystem |
| **Auto-Fix** | Yes |
| **CVSS Score** | 7.5 |

## Description

The main configuration file `~/.moltbot/moltbot.json` is readable by other users on the system, potentially exposing:

- Gateway authentication tokens
- API keys (if stored directly)
- Channel configurations
- Sensitive settings

## Affected Files in Moltbot

- `~/.moltbot/moltbot.json`
- `src/security/audit-fs.ts` - Permission checking
- `src/security/fix.ts` - Permission fixing

## Detection

```go
func (c *ConfigPermsCheck) Run(ctx *CheckContext) ([]Finding, error) {
    perms, err := inspectPermissions(ctx.ConfigPath)
    if err != nil {
        return nil, err
    }

    if perms.WorldReadable || perms.GroupReadable {
        return []Finding{{
            CheckID:  "V17",
            Severity: SeverityCritical,
            Title:    "Config file readable by others",
            Detail:   fmt.Sprintf("permissions: %o", perms.Mode),
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```bash
chmod 600 ~/.moltbot/moltbot.json
```

## Manual Fix Instructions

```bash
chmod 600 ~/.moltbot/moltbot.json

# Verify
ls -la ~/.moltbot/moltbot.json
# Should show: -rw-------
```

## Verification Steps

```bash
# Check permissions
stat -f "%A %N" ~/.moltbot/moltbot.json
# Should show: 600

# Test as other user
sudo -u nobody cat ~/.moltbot/moltbot.json
# Should fail
```

## Related Vulnerabilities

- [V04: Plaintext Credentials](V04-plaintext-credentials.md)
- [V18: State Directory Exposure](V18-state-dir-exposure.md)

## References

- [Moltbot Security - File Permissions](https://docs.molt.bot/gateway/security#file-permissions)
