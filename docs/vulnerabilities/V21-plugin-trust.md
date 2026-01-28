# V21: Plugin Trust Boundary

## Overview

| Property | Value |
|----------|-------|
| **ID** | V21 |
| **Severity** | High |
| **Category** | Plugins |
| **Auto-Fix** | Yes |
| **CVSS Score** | 7.2 |

## Description

Extensions/plugins exist in the state directory but no explicit `plugins.allow` list is configured. This means:

- Any discovered plugin may load
- Malicious plugins could execute code
- No audit trail of trusted plugins

## Affected Files in Moltbot

- `src/plugins/runtime/index.ts` - Plugin loading
- `src/security/audit-extra.ts` - Plugin trust checks
- `~/.moltbot/extensions/` - Installed plugins

## Detection

```go
func (c *PluginTrustCheck) Run(ctx *CheckContext) ([]Finding, error) {
    extensionsDir := filepath.Join(ctx.StateDir, "extensions")
    plugins, _ := ioutil.ReadDir(extensionsDir)

    if len(plugins) > 0 && len(ctx.Config.Plugins.Allow) == 0 {
        return []Finding{{
            CheckID:  "V21",
            Severity: SeverityHigh,
            Title:    "Extensions exist without allowlist",
            Detail:   fmt.Sprintf("%d extensions, no plugins.allow", len(plugins)),
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```json
{
  "plugins": {
    "allow": []
  }
}
```

Or with known trusted plugins:

```json
{
  "plugins": {
    "allow": ["@moltbot/voice-call", "@moltbot/matrix"]
  }
}
```

## Manual Fix Instructions

### Set Explicit Allowlist

```bash
# List installed plugins
ls ~/.moltbot/extensions/

# Allow only trusted ones
moltbot config set plugins.allow '["@moltbot/voice-call"]'
```

### Remove Untrusted Plugins

```bash
# Remove plugin
rm -rf ~/.moltbot/extensions/suspicious-plugin

# Restart gateway
```

## Verification Steps

```bash
moltbot config get plugins.allow
# Should list only trusted plugins

ls ~/.moltbot/extensions/
# Should only contain allowed plugins
```

## Related Vulnerabilities

- [V06: Dangerous Commands Enabled](V06-dangerous-commands.md)

## References

- [Moltbot Plugins Documentation](https://docs.molt.bot/plugin)
- [Plugin Security](https://docs.molt.bot/gateway/security#plugins)
