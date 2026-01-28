# V49: Session Key Collision via Normalization

**Severity:** MEDIUM
**Category:** Routing
**Auto-Fix:** No (requires code change)

## Description

Invalid characters in identifiers are normalized to hyphens, causing potential collisions. Two distinct users could end up sharing the same session.

## Affected Code

- `src/routing/session-key.ts:57-98`

## Examples

```
foo_bar  →  foo-bar
foo@bar  →  foo-bar
foo.bar  →  foo-bar
```

All three normalize to the same session key!

## Risk

- Cross-user session sharing
- Context leakage between users
- Conversation history mixing
- Privacy violation

## Detection

```typescript
// Test normalization
console.log(normalizeAgentId("foo_bar"));  // foo-bar
console.log(normalizeAgentId("foo@bar"));  // foo-bar
// Same output = collision
```

## Remediation

1. Use collision-resistant encoding:
```typescript
function normalizeAgentId(id: string): string {
  // Base64 encode to preserve uniqueness
  return Buffer.from(id).toString("base64url");
}
```

2. Or reject invalid characters:
```typescript
function normalizeAgentId(id: string): string {
  const VALID = /^[a-zA-Z0-9-]+$/;
  if (!VALID.test(id)) {
    throw new Error(`Invalid agent ID: ${id}`);
  }
  return id.toLowerCase();
}
```

3. Add collision detection:
```typescript
const sessionKeys = new Map<string, string>();

function getSessionKey(userId: string): string {
  const normalized = normalize(userId);
  const existing = sessionKeys.get(normalized);

  if (existing && existing !== userId) {
    throw new Error(`Session key collision: ${userId} vs ${existing}`);
  }

  sessionKeys.set(normalized, userId);
  return normalized;
}
```

## References

- [CWE-706: Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)
