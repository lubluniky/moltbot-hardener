# V20: Tailscale Funnel Exposure

## Overview

| Property | Value |
|----------|-------|
| **ID** | V20 |
| **Severity** | Critical |
| **Category** | Gateway |
| **Auto-Fix** | Yes |
| **CVSS Score** | 9.0 |

## Description

Tailscale Funnel is enabled, exposing the gateway to the public internet. This creates attack surface from:

- Anyone on the internet
- Automated scanners
- Targeted attacks

## Affected Files in Moltbot

- `src/gateway/tailscale.ts` - Tailscale integration
- `src/security/audit.ts` - Funnel detection

## Detection

```go
func (c *TailscaleFunnelCheck) Run(ctx *CheckContext) ([]Finding, error) {
    mode := ctx.Config.Gateway.Tailscale.Mode

    if mode == "funnel" {
        return []Finding{{
            CheckID:  "V20",
            Severity: SeverityCritical,
            Title:    "Tailscale Funnel exposes gateway publicly",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```json
{
  "gateway": {
    "tailscale": {
      "mode": "serve"
    }
  }
}
```

## Manual Fix Instructions

### Switch to Serve (Tailnet Only)

```bash
moltbot config set gateway.tailscale.mode serve
```

### Disable Tailscale Exposure

```bash
moltbot config set gateway.tailscale.mode off
```

## Verification Steps

```bash
moltbot config get gateway.tailscale.mode
# Should return: serve or off

# Check Tailscale status
tailscale status
# Verify no funnel endpoints
```

## Tailscale Modes

| Mode | Exposure | Recommended |
|------|----------|-------------|
| `off` | None | Yes |
| `serve` | Tailnet only | Yes |
| `funnel` | Public internet | No |

## Related Vulnerabilities

- [V01: Gateway Exposure](V01-gateway-exposure.md)

## References

- [Moltbot Tailscale Documentation](https://docs.molt.bot/gateway/tailscale)
- [Tailscale Funnel Risks](https://tailscale.com/kb/1223/funnel)
