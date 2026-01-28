# V23: Control UI Insecure Auth

## Overview

| Property | Value |
|----------|-------|
| **ID** | V23 |
| **Severity** | Critical |
| **Category** | Gateway |
| **Auto-Fix** | Yes |
| **CVSS Score** | 8.1 |

## Description

The Control UI is configured to allow insecure authentication:

- `allowInsecureAuth: true` - Allows token auth over HTTP
- `dangerouslyDisableDeviceAuth: true` - Disables device identity

This enables authentication bypass and session hijacking.

## Affected Files in Moltbot

- `src/gateway/control-ui.ts` - Control UI settings
- `src/security/audit.ts` - Insecure auth detection

## Detection

```go
func (c *ControlUICheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    if ctx.Config.Gateway.ControlUI.AllowInsecureAuth {
        findings = append(findings, Finding{
            CheckID:  "V23",
            Severity: SeverityCritical,
            Title:    "Control UI allows insecure HTTP auth",
        })
    }

    if ctx.Config.Gateway.ControlUI.DangerouslyDisableDeviceAuth {
        findings = append(findings, Finding{
            CheckID:  "V23",
            Severity: SeverityCritical,
            Title:    "Control UI device auth disabled",
        })
    }

    return findings, nil
}
```

## Fix Applied by Hardener

```json
{
  "gateway": {
    "controlUi": {
      "allowInsecureAuth": false,
      "dangerouslyDisableDeviceAuth": false
    }
  }
}
```

## Manual Fix Instructions

```bash
moltbot config set gateway.controlUi.allowInsecureAuth false
moltbot config set gateway.controlUi.dangerouslyDisableDeviceAuth false
```

## Verification Steps

```bash
moltbot config get gateway.controlUi.allowInsecureAuth
# Should return: false

moltbot config get gateway.controlUi.dangerouslyDisableDeviceAuth
# Should return: false
```

## Secure Control UI Access

- Use HTTPS (via Tailscale Serve)
- Access only on localhost
- Never expose over plain HTTP

## Related Vulnerabilities

- [V01: Gateway Exposure](V01-gateway-exposure.md)
- [V20: Tailscale Funnel Exposure](V20-tailscale-funnel.md)

## References

- [Moltbot Control UI Security](https://docs.molt.bot/gateway/security#control-ui-over-http)
