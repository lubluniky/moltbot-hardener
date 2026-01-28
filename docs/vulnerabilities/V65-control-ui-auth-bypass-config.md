# V65: Control UI Auth Bypass Configuration

**Severity:** LOW
**Category:** Configuration
**Auto-Fix:** Yes (config)

## Description

Configuration options `allowInsecureAuth` and `dangerouslyDisableDeviceAuth` exist that can weaken security when enabled.

## Affected Code

- `src/gateway/server/ws-connection/message-handler.ts:371-376`

## Risk

- Authentication bypass when misconfigured
- Accidental security weakening
- Persistent vulnerability if forgotten

## Detection

```bash
# Check for insecure settings
moltbot config get controlUI.allowInsecureAuth
moltbot config get controlUI.dangerouslyDisableDeviceAuth
```

## Remediation

1. Ensure settings are disabled:
```bash
moltbot config set controlUI.allowInsecureAuth false
moltbot config set controlUI.dangerouslyDisableDeviceAuth false
```

2. Add startup warnings in code:
```typescript
if (config.allowInsecureAuth) {
  log.warn("⚠️  SECURITY WARNING: allowInsecureAuth is enabled");
  log.warn("⚠️  This weakens authentication security");
}

if (config.dangerouslyDisableDeviceAuth) {
  log.error("🚨 CRITICAL: Device authentication is DISABLED");
  log.error("🚨 Any device can connect to the gateway");
}
```

3. Require confirmation for dangerous settings:
```typescript
async function setConfig(key: string, value: any) {
  const dangerous = ["allowInsecureAuth", "dangerouslyDisableDeviceAuth"];

  if (dangerous.includes(key) && value === true) {
    const confirmed = await prompt(
      `⚠️  Setting ${key}=true is dangerous. Type 'I UNDERSTAND' to confirm: `
    );
    if (confirmed !== "I UNDERSTAND") {
      throw new Error("Confirmation required for dangerous settings");
    }
  }

  // Set the config
}
```

## Quick Fix

```bash
moltbot config set controlUI.allowInsecureAuth false
moltbot config set controlUI.dangerouslyDisableDeviceAuth false
```

## References

- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
