# V27: Timing Attack on Token Comparison

**Severity:** HIGH
**Category:** Authentication
**Auto-Fix:** No (requires code change)

## Description

Token verification uses direct string comparison (`===` or `!==`) instead of constant-time comparison (`crypto.timingSafeEqual()`). This allows attackers to guess tokens character by character by measuring response times.

## Affected Code

- `src/infra/device-pairing.ts:396` - `entry.token !== params.token`
- `src/infra/node-pairing.ts:271` - `node.token === token`

## Attack Scenario

1. Attacker sends token guess "AAAA..."
2. Server compares character by character, fails fast on first mismatch
3. Attacker measures response time
4. If first char matches, comparison takes slightly longer
5. Repeat for each character position to deduce full token

## Risk

- Token theft via network timing analysis
- Device impersonation
- Unauthorized access to gateway

## Detection

```bash
# Code review - search for direct token comparisons
grep -r "token ===" src/
grep -r "token !==" src/
```

## Remediation

Replace direct comparisons with timing-safe comparison:

```typescript
import { timingSafeEqual } from 'crypto';

function safeTokenCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
```

## References

- [Node.js crypto.timingSafeEqual](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
