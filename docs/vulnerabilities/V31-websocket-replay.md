# V31: WebSocket Handshake Replay

**Severity:** LOW
**Category:** Authentication
**Auto-Fix:** No (requires code change)

## Description

Device signatures are valid for 10 minutes (`DEVICE_SIGNATURE_SKEW_MS`), allowing replay attacks within this window. For local clients, legacy signatures without nonces are still accepted.

## Affected Code

- `src/gateway/server/ws-connection/message-handler.ts:61`
- `DEVICE_SIGNATURE_SKEW_MS = 10 * 60 * 1000`

## Risk

- Captured handshake can be replayed within 10 minutes
- Man-in-the-middle can impersonate devices
- Legacy signature support weakens security

## Detection

```typescript
// Check the skew value
console.log(DEVICE_SIGNATURE_SKEW_MS); // 600000 = 10 minutes
```

## Remediation

1. Reduce signature validity window:
```typescript
const DEVICE_SIGNATURE_SKEW_MS = 60 * 1000; // 60 seconds
```

2. Implement server-side nonce tracking:
```typescript
const usedNonces = new Set<string>();

function validateSignature(sig: DeviceSignature): boolean {
  if (usedNonces.has(sig.nonce)) {
    return false; // Replay detected
  }
  usedNonces.add(sig.nonce);
  // Clean old nonces periodically
  return verifySignature(sig);
}
```

3. Require nonces for all connections (deprecate legacy)

## References

- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
