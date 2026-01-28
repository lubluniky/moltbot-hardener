# V63: mDNS Exposes Internal Ports

**Severity:** LOW
**Category:** Information Disclosure
**Auto-Fix:** Yes (config)

## Description

Bonjour/mDNS advertisement exposes internal configuration including gateway port, SSH port, CLI path, and canvas port.

## Affected Code

- `src/infra/bonjour.ts:105-148`

## Exposed Information

- `gatewayPort` - Gateway service port
- `sshPort` - SSH port (if not minimal mode)
- `cliPath` - Full path to CLI binary
- `canvasPort` - Canvas service port
- `tailnetDns` - Tailscale DNS name

## Risk

- Network reconnaissance
- Attack surface mapping
- Internal path disclosure

## Detection

```bash
# Scan for mDNS services
dns-sd -B _moltbot._tcp local.
dns-sd -L "Moltbot" _moltbot._tcp local.

# Or with avahi
avahi-browse -r _moltbot._tcp
```

## Remediation

1. Disable mDNS:
```bash
moltbot config set gateway.mdns false
moltbot config set gateway.bonjour false
```

2. Enable minimal mode (reduces exposed info):
```bash
moltbot config set gateway.mdns.minimal true
```

3. In code, remove sensitive fields:
```typescript
const txtRecord = {
  version: pkg.version,
  // Remove: gatewayPort, sshPort, cliPath, canvasPort
};
```

## Quick Fix

```bash
moltbot config set gateway.mdns false
moltbot config set gateway.bonjour false
```

## References

- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
