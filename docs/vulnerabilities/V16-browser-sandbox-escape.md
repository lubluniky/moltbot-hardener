# V16: Browser Sandbox Escape

## Overview

| Property | Value |
|----------|-------|
| **ID** | V16 |
| **Severity** | Critical |
| **Category** | Tools |
| **Auto-Fix** | Yes |
| **CVSS Score** | 8.8 |

## Description

Sandboxed sessions can access the host browser control, effectively escaping the sandbox:

- Access logged-in browser sessions
- Read cookies and credentials
- Control authenticated web applications
- Browse as the host user

## Affected Files in Moltbot

- `src/config/types.sandbox.ts` - Browser sandbox settings
- `src/agents/sandbox/browser.ts` - Browser control
- `src/browser/config.ts` - Browser configuration

## Attack Scenario

1. **Sandbox Access**: Attacker in sandboxed session
2. **Browser Tool**: Uses browser control tool
3. **Host Access**: If `allowHostControl: true`, accesses host browser
4. **Exploitation**: Uses logged-in sessions (banking, email, etc.)

## Detection

```go
func (c *BrowserSandboxCheck) Run(ctx *CheckContext) ([]Finding, error) {
    allowHost := ctx.Config.Agents.Defaults.Sandbox.Browser.AllowHostControl

    if allowHost {
        return []Finding{{
            CheckID:  "V16",
            Severity: SeverityCritical,
            Title:    "Sandbox allows host browser control",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "browser": {
          "enabled": false,
          "allowHostControl": false
        }
      }
    }
  }
}
```

## Manual Fix Instructions

### Disable Host Browser Access

```bash
moltbot config set agents.defaults.sandbox.browser.allowHostControl false
```

### Disable Browser in Sandbox

```bash
moltbot config set agents.defaults.sandbox.browser.enabled false
```

### Use Isolated Browser Container

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "browser": {
          "enabled": true,
          "allowHostControl": false,
          "image": "ghcr.io/moltbot/sandbox-browser:latest"
        }
      }
    }
  }
}
```

## Verification Steps

1. **Check browser settings**:
   ```bash
   moltbot config get agents.defaults.sandbox.browser.allowHostControl
   # Should return: false
   ```

2. **Test from sandboxed session**:
   - Request browser action
   - Should use sandbox browser, not host

## Related Vulnerabilities

- [V03: Sandbox Disabled](V03-sandbox-disabled.md)
- [V06: Dangerous Commands Enabled](V06-dangerous-commands.md)

## References

- [Moltbot Browser Tool](https://docs.molt.bot/tools/browser)
- [Browser Security Notes](https://docs.molt.bot/gateway/security#browser-control-risks)
