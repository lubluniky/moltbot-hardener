# V25: Group Policy Open

## Overview

| Property | Value |
|----------|-------|
| **ID** | V25 |
| **Severity** | Critical |
| **Category** | Channels |
| **Auto-Fix** | Yes |
| **CVSS Score** | 8.6 |

## Description

One or more channels have `groupPolicy: "open"`, allowing any group member to interact with the agent. Combined with elevated tools, this is extremely dangerous as prompt injection from any group member can lead to host compromise.

## Affected Files in Moltbot

- `src/security/audit-extra.ts` - Group policy checks
- `src/security/audit.ts` - Exposure matrix
- Channel config types

## Attack Scenario

1. **Group Access**: Agent is in group with open policy
2. **Member Attack**: Any group member sends malicious message
3. **Prompt Injection**: Tricks agent into running commands
4. **Impact**: Full tool access if elevated is enabled

## Detection

```go
func (c *GroupPolicyCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    openGroups := c.listOpenGroupPolicies(ctx.Config)
    elevatedEnabled := ctx.Config.Tools.Elevated.Enabled

    for _, path := range openGroups {
        severity := SeverityHigh
        if elevatedEnabled {
            severity = SeverityCritical
        }

        findings = append(findings, Finding{
            CheckID:  "V25",
            Severity: severity,
            Title:    "Group policy is open",
            Detail:   path,
        })
    }

    return findings, nil
}
```

## Fix Applied by Hardener

```json
{
  "channels": {
    "whatsapp": {
      "groupPolicy": "allowlist"
    },
    "telegram": {
      "groupPolicy": "allowlist"
    },
    "discord": {
      "groupPolicy": "allowlist"
    }
  }
}
```

## Manual Fix Instructions

### Set Allowlist Policy

```bash
moltbot config set channels.whatsapp.groupPolicy allowlist
moltbot config set channels.telegram.groupPolicy allowlist
moltbot config set channels.discord.groupPolicy allowlist
```

### Require Mention

```bash
moltbot config set channels.whatsapp.groups.*.requireMention true
```

### Per-Account Settings

```json
{
  "channels": {
    "whatsapp": {
      "accounts": {
        "default": {
          "groupPolicy": "allowlist"
        }
      }
    }
  }
}
```

## Verification Steps

```bash
moltbot security audit | grep -i "group.*open"
# Should return nothing

moltbot config get channels.whatsapp.groupPolicy
# Should return: allowlist
```

## Group Policy Options

| Policy | Access | Security |
|--------|--------|----------|
| `open` | Any member | None |
| `allowlist` | Explicit only | High |
| `disabled` | No groups | Maximum |

## Related Vulnerabilities

- [V02: DM Policy Open](V02-dm-policy-open.md)
- [V05: Prompt Injection Surface](V05-prompt-injection.md)
- [V08: Elevated Tool Access](V08-elevated-tool-access.md)

## References

- [Moltbot Groups Documentation](https://docs.molt.bot/concepts/groups)
- [Security - Open Groups](https://docs.molt.bot/gateway/security#exposure-matrix)
