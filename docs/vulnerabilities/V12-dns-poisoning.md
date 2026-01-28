# V12: DNS Poisoning Risk

## Overview

| Property | Value |
|----------|-------|
| **ID** | V12 |
| **Severity** | Medium |
| **Category** | Tools |
| **Auto-Fix** | Yes |
| **CVSS Score** | 6.1 |

## Description

Sandbox containers use default DNS resolution, which can be:

- Poisoned by network attackers
- Used for data exfiltration via DNS queries
- Manipulated to redirect traffic

## Affected Files in Moltbot

- `src/agents/sandbox/docker.ts` - DNS configuration
- `src/config/types.sandbox.ts` - Docker settings

## Attack Scenario

1. **Network Position**: Attacker on same network as gateway
2. **DNS Spoof**: Sends spoofed DNS responses
3. **Redirect**: Container connects to attacker-controlled server
4. **Exploitation**: Data theft, credential capture

## Detection

```go
func (c *DNSPoisoningCheck) Run(ctx *CheckContext) ([]Finding, error) {
    dns := ctx.Config.Agents.Defaults.Sandbox.Docker.DNS
    network := ctx.Config.Agents.Defaults.Sandbox.Docker.Network

    if network != "none" && len(dns) == 0 {
        return []Finding{{
            CheckID:  "V12",
            Severity: SeverityMedium,
            Title:    "No explicit DNS servers configured",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

For network-enabled containers:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "docker": {
          "dns": ["1.1.1.1", "8.8.8.8"]
        }
      }
    }
  }
}
```

Or better, disable network entirely:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "docker": {
          "network": "none"
        }
      }
    }
  }
}
```

## Manual Fix Instructions

### Disable Network (Recommended)

```bash
moltbot config set agents.defaults.sandbox.docker.network none
```

### Set Explicit DNS

```bash
moltbot config set agents.defaults.sandbox.docker.dns '["1.1.1.1", "8.8.8.8"]'
```

## Verification Steps

1. **Check DNS config**:
   ```bash
   moltbot config get agents.defaults.sandbox.docker.dns
   ```

2. **Test container DNS**:
   ```bash
   docker exec moltbot-sandbox-test cat /etc/resolv.conf
   ```

## Related Vulnerabilities

- [V07: No Network Isolation](V07-no-network-isolation.md)

## References

- [Docker DNS Configuration](https://docs.docker.com/config/containers/container-networking/#dns-services)
