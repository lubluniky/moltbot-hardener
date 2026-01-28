# V66: Pairing Code Brute Force

**Severity:** LOW
**Category:** Authentication
**Auto-Fix:** Partial (config)

## Description

No rate limiting on pairing code verification attempts. While codes have ~10^12 combinations, persistent brute force is possible.

## Affected Code

- `src/pairing/pairing-store.ts`

## Risk

- Brute force pairing codes
- Unauthorized device pairing
- Account takeover

## Detection

```bash
# Monitor pairing attempts in logs
grep "pairing" ~/.clawdbot/audit.log
```

## Remediation

1. Rate limit verification:
```typescript
const verifyAttempts = new Map<string, number>();
const MAX_VERIFY_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;  // 15 minutes

async function verifyPairingCode(code: string, ip: string): Promise<boolean> {
  const attempts = verifyAttempts.get(ip) || 0;

  if (attempts >= MAX_VERIFY_ATTEMPTS) {
    throw new Error("Too many attempts. Try again later.");
  }

  verifyAttempts.set(ip, attempts + 1);

  // Clean up after lockout
  setTimeout(() => verifyAttempts.delete(ip), LOCKOUT_MS);

  return checkCode(code);
}
```

2. Exponential backoff:
```typescript
const backoffMs = Math.min(1000 * Math.pow(2, attempts), 30000);
await sleep(backoffMs);
```

3. Increase code strength:
```bash
moltbot config set pairing.codeLength 10
moltbot config set pairing.expiry 180  # 3 minutes
```

## Config Fix

```bash
moltbot config set pairing.codeLength 10
moltbot config set pairing.expiry 180
moltbot config set pairing.maxAttempts 3
```

## References

- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
