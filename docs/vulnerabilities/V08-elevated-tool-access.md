# V08: Elevated Tool Access

## Overview

| Property | Value |
|----------|-------|
| **ID** | V08 |
| **Severity** | Critical |
| **Category** | Tools |
| **Auto-Fix** | Yes |
| **CVSS Score** | 9.5 |

## Description

Elevated mode is enabled with a permissive allowlist (including wildcard `*`), allowing tool execution to bypass sandbox restrictions and run directly on the gateway host. This is essentially remote code execution for anyone in the allowlist.

## Affected Files in Moltbot

- `src/agents/bash-tools.exec.ts` - Elevated execution path
- `src/config/types.tools.ts` - Elevated configuration
- `src/security/audit.ts` - Elevated allowlist checks
- `src/auto-reply/reply/reply-elevated.ts` - Elevated mode handling

## Attack Scenario

1. **Allowlist Entry**: Attacker is in elevated allowlist (or wildcard used)
2. **Trigger**: Sends message requesting elevated command:
   ```
   !elevated run: rm -rf /important/data
   ```
3. **Execution**: Command runs on gateway host, not in sandbox
4. **Impact**: Full host compromise

### Attack Vector

```
Allowlisted User -> Elevated Command -> Host Execution -> Full Access
```

## Detection

```go
func (c *ElevatedToolCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    if ctx.Config.Tools.Elevated.Enabled == false {
        return nil, nil  // Disabled is safe
    }

    for provider, allowFrom := range ctx.Config.Tools.Elevated.AllowFrom {
        for _, entry := range allowFrom {
            if entry == "*" {
                findings = append(findings, Finding{
                    CheckID:  "V08",
                    Severity: SeverityCritical,
                    Title:    "Elevated mode allows wildcard",
                    Detail:   fmt.Sprintf("tools.elevated.allowFrom.%s contains '*'", provider),
                })
            }
        }

        if len(allowFrom) > 25 {
            findings = append(findings, Finding{
                CheckID:  "V08",
                Severity: SeverityHigh,
                Title:    "Elevated allowlist is large",
                Detail:   fmt.Sprintf("%d entries in %s", len(allowFrom), provider),
            })
        }
    }

    return findings, nil
}
```

## Fix Applied by Hardener

The hardener removes wildcards and optionally disables elevated mode:

```json
{
  "tools": {
    "elevated": {
      "enabled": false
    }
  }
}
```

Or restricts to explicit list:

```json
{
  "tools": {
    "elevated": {
      "enabled": true,
      "allowFrom": {
        "whatsapp": ["+1234567890"],
        "telegram": ["@owner_username"]
      }
    }
  }
}
```

## Manual Fix Instructions

### Disable Elevated Mode

```bash
moltbot config set tools.elevated.enabled false
```

### Remove Wildcards

```bash
# Check current allowlist
moltbot config get tools.elevated.allowFrom

# Set explicit allowlist (no wildcards)
moltbot config set tools.elevated.allowFrom.whatsapp '["your-number"]'
```

### Per-Agent Elevated Restrictions

```json
{
  "agents": {
    "list": [
      {
        "id": "family",
        "tools": {
          "elevated": {
            "enabled": false
          }
        }
      }
    ]
  }
}
```

## Verification Steps

1. **Check elevated status**:
   ```bash
   moltbot config get tools.elevated.enabled
   # Should return: false (or carefully controlled allowlist)
   ```

2. **Check for wildcards**:
   ```bash
   moltbot config get tools.elevated.allowFrom | grep '*'
   # Should return nothing
   ```

3. **Run security audit**:
   ```bash
   moltbot security audit
   # Should not warn about elevated allowlist
   ```

## Elevated Mode Use Cases

Only enable elevated mode if you:
- Need host-level operations that can't run in sandbox
- Trust the allowlisted users completely
- Understand this bypasses all sandboxing

## Related Vulnerabilities

- [V03: Sandbox Disabled](V03-sandbox-disabled.md)
- [V06: Dangerous Commands Enabled](V06-dangerous-commands.md)
- [V25: Group Policy Open](V25-group-policy-open.md)

## References

- [Moltbot Elevated Mode Documentation](https://docs.molt.bot/tools/elevated)
- [Security - Tool Blast Radius](https://docs.molt.bot/gateway/security#tool-blast-radius)
