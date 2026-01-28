# V11: Unrestricted Bind Mounts

## Overview

| Property | Value |
|----------|-------|
| **ID** | V11 |
| **Severity** | High |
| **Category** | Tools |
| **Auto-Fix** | Yes |
| **CVSS Score** | 7.8 |

## Description

Sandbox containers have bind mounts that expose sensitive host paths:

- Root filesystem mounts
- Home directory access
- SSH keys and credentials
- System configuration files

This defeats the purpose of sandboxing by giving container access to host resources.

## Affected Files in Moltbot

- `src/agents/sandbox/docker.ts` - Bind mount configuration
- `src/config/types.sandbox.ts` - Docker settings types
- `src/agents/sandbox/config.ts` - Sandbox configuration

## Attack Scenario

1. **Container Access**: Attacker compromises sandboxed session
2. **Mount Discovery**: Finds bind mount to sensitive path
3. **Exploitation**: Accesses credentials, SSH keys, or system files
4. **Escape**: Uses accessed credentials for host access

### Dangerous Mounts

| Path | Risk |
|------|------|
| `/` | Full system access |
| `/home` | All user data |
| `~/.ssh` | SSH keys |
| `~/.aws` | AWS credentials |
| `/etc` | System configuration |
| `/var/run/docker.sock` | Docker escape |

## Detection

```go
func (c *BindMountCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    dangerousPaths := []string{
        "/", "/home", "/root", "/etc",
        ".ssh", ".aws", ".gnupg",
        "/var/run/docker.sock",
    }

    for _, bind := range ctx.Config.Agents.Defaults.Sandbox.Docker.Binds {
        hostPath := strings.Split(bind, ":")[0]
        for _, dangerous := range dangerousPaths {
            if strings.Contains(hostPath, dangerous) {
                findings = append(findings, Finding{
                    CheckID:  "V11",
                    Severity: SeverityHigh,
                    Title:    "Dangerous bind mount",
                    Detail:   fmt.Sprintf("bind: %s", bind),
                })
            }
        }
    }

    return findings, nil
}
```

## Fix Applied by Hardener

The hardener removes dangerous bind mounts:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "docker": {
          "binds": []
        }
      }
    }
  }
}
```

## Manual Fix Instructions

### Remove Dangerous Mounts

```bash
# Check current binds
moltbot config get agents.defaults.sandbox.docker.binds

# Remove all binds
moltbot config set agents.defaults.sandbox.docker.binds '[]'
```

### Use Workspace Only

```bash
# Only mount the sandbox workspace
moltbot config set agents.defaults.sandbox.workspaceAccess ro
# This mounts ~/.moltbot/sandboxes/<id> to /workspace
```

### Safe Mount Pattern

If you need specific mounts:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "docker": {
          "binds": [
            "/path/to/safe/data:/data:ro"
          ]
        }
      }
    }
  }
}
```

Always use `:ro` for read-only when possible.

## Verification Steps

1. **Check bind mounts**:
   ```bash
   moltbot config get agents.defaults.sandbox.docker.binds
   # Should be empty or contain only safe paths
   ```

2. **Inspect running container**:
   ```bash
   docker inspect moltbot-sandbox-* | jq '.[].Mounts'
   ```

3. **Test access from container**:
   ```bash
   docker exec moltbot-sandbox-test ls /
   # Should only show container filesystem
   ```

## Related Vulnerabilities

- [V03: Sandbox Disabled](V03-sandbox-disabled.md)
- [V07: No Network Isolation](V07-no-network-isolation.md)

## References

- [Docker Bind Mounts Security](https://docs.docker.com/storage/bind-mounts/)
- [Container Escape Techniques](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
