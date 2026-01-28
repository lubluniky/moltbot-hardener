# V59: No Rate Limit on Pairing Generation

**Severity:** MEDIUM
**Category:** Rate Limiting
**Auto-Fix:** Partial (config)

## Description

Pairing codes can be generated without rate limiting by sending messages from different sender IDs. An attacker can enumerate many valid pairing codes.

## Affected Code

- `src/telegram/pairing-store.ts`
- `src/discord/pairing-store.ts`
- `src/slack/pairing-store.ts`

## Risk

- Pairing code enumeration
- Resource exhaustion
- Potential brute force if codes are weak

## Attack Scenario

```bash
# Generate 1000 pairing codes from different fake senders
for i in $(seq 1 1000); do
  send_message --from "user$i" --text "!pair"
done
# Now attacker has 1000 valid pairing codes to try
```

## Detection

```bash
# Check pending pairing requests
moltbot pairing list
```

## Remediation

1. Global rate limit on code generation:
```typescript
const pairingRateLimit = new RateLimiter({
  maxRequests: 10,
  windowMs: 60000  // 10 per minute
});

async function generatePairingCode(senderId: string): Promise<string> {
  if (!pairingRateLimit.check()) {
    throw new Error("Too many pairing requests");
  }
  // Generate code
}
```

2. Limit total pending requests:
```typescript
const MAX_PENDING_PAIRING = 50;

async function generatePairingCode(senderId: string): Promise<string> {
  const pending = await countPendingPairings();
  if (pending >= MAX_PENDING_PAIRING) {
    throw new Error("Too many pending pairing requests");
  }
  // Generate code
}
```

3. Per-IP rate limiting (where applicable):
```typescript
const ipRateLimit = new Map<string, number>();
```

## Config Fix

```bash
moltbot config set pairing.rateLimit 5
moltbot config set pairing.maxPending 50
```

## References

- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
