# V26: mDNS Information Disclosure

## Overview

| Property | Value |
|----------|-------|
| **ID** | V26 |
| **Severity** | Medium |
| **Category** | Gateway |
| **Auto-Fix** | Yes |
| **CVSS Score** | 4.3 |

## Description

mDNS/Bonjour discovery is broadcasting sensitive information about the gateway installation:

- Full CLI path (reveals username, install location)
- SSH port availability
- Hostname and LAN address

This information aids reconnaissance for targeted attacks.

## Affected Files in Moltbot

- `src/infra/bonjour.ts` - mDNS broadcasting
- `src/config/types.ts` - Discovery settings

## TXT Records Exposed (Full Mode)

| Field | Information | Risk |
|-------|-------------|------|
| `cliPath` | `/Users/victim/.../moltbot` | Username leak |
| `sshPort` | `22` | Attack vector |
| `displayName` | Hostname | Identification |
| `lanHost` | IP address | Network mapping |

## Detection

```go
func (c *MDNSCheck) Run(ctx *CheckContext) ([]Finding, error) {
    mode := ctx.Config.Discovery.MDNS.Mode
    if mode == "" {
        mode = "full"  // Legacy default
    }

    if mode == "full" {
        return []Finding{{
            CheckID:  "V26",
            Severity: SeverityMedium,
            Title:    "mDNS broadcasts sensitive info",
            Detail:   "discovery.mdns.mode=full exposes cliPath and sshPort",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```json
{
  "discovery": {
    "mdns": {
      "mode": "minimal"
    }
  }
}
```

Or disable entirely:

```json
{
  "discovery": {
    "mdns": {
      "mode": "off"
    }
  }
}
```

## Manual Fix Instructions

### Use Minimal Mode

```bash
moltbot config set discovery.mdns.mode minimal
```

### Disable mDNS

```bash
moltbot config set discovery.mdns.mode off

# Or via environment
export CLAWDBOT_DISABLE_BONJOUR=1
```

## Verification Steps

```bash
moltbot config get discovery.mdns.mode
# Should return: minimal or off

# Test mDNS discovery
dns-sd -B _moltbot-gw._tcp local.
# Should not find service (if off)
# Or should not have cliPath/sshPort (if minimal)
```

## mDNS Modes

| Mode | Broadcast | Recommended |
|------|-----------|-------------|
| `off` | Nothing | Yes (if no local discovery needed) |
| `minimal` | Basic info only | Yes |
| `full` | All fields | No |

## Related Vulnerabilities

- [V01: Gateway Exposure](V01-gateway-exposure.md)

## References

- [Moltbot mDNS Configuration](https://docs.molt.bot/gateway/security#mdns-bonjour-discovery)
