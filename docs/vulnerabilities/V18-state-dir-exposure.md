# V18: State Directory Exposure

## Overview

| Property | Value |
|----------|-------|
| **ID** | V18 |
| **Severity** | Critical |
| **Category** | Filesystem |
| **Auto-Fix** | Yes |
| **CVSS Score** | 7.5 |

## Description

The moltbot state directory `~/.moltbot/` is accessible to other users, exposing:

- Session transcripts
- Credentials
- Auth profiles
- Sandbox workspaces

## Detection

```go
func (c *StateDirCheck) Run(ctx *CheckContext) ([]Finding, error) {
    perms, err := inspectPermissions(ctx.StateDir)
    if err != nil {
        return nil, err
    }

    if perms.WorldWritable || perms.GroupWritable {
        return []Finding{{
            CheckID:  "V18",
            Severity: SeverityCritical,
            Title:    "State directory writable by others",
        }}, nil
    }

    if perms.WorldReadable || perms.GroupReadable {
        return []Finding{{
            CheckID:  "V18",
            Severity: SeverityHigh,
            Title:    "State directory readable by others",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```bash
chmod 700 ~/.moltbot
chmod 700 ~/.moltbot/credentials
chmod 700 ~/.moltbot/agents/*/agent
chmod 700 ~/.moltbot/agents/*/sessions
```

## Manual Fix Instructions

```bash
chmod 700 ~/.moltbot
find ~/.moltbot -type d -exec chmod 700 {} \;
find ~/.moltbot -type f -exec chmod 600 {} \;
```

## Verification Steps

```bash
ls -la ~ | grep moltbot
# Should show: drwx------
```

## Related Vulnerabilities

- [V04: Plaintext Credentials](V04-plaintext-credentials.md)
- [V17: World-Readable Config](V17-world-readable-config.md)
