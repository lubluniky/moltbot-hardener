# V58: Thread ID Integer Overflow

**Severity:** LOW
**Category:** Input Validation
**Auto-Fix:** No (requires code change)

## Description

Large thread IDs are parsed with `parseInt` which may overflow on platforms with 32-bit integer limits or cause unexpected behavior.

## Affected Code

- `src/channels/plugins/outbound/telegram.ts:11-20`

## Risk

- Integer overflow
- Session key collisions
- Unexpected behavior with large IDs

## Attack Scenario

```typescript
// Very large thread ID
const threadId = "99999999999999999999";
const parsed = parseInt(threadId, 10);
// parsed = 1e+20 (loses precision)

// Or with BigInt conversion issues
const threadId = "9007199254740993";  // > Number.MAX_SAFE_INTEGER
parseInt(threadId) === parseInt("9007199254740992")  // true!
```

## Detection

```typescript
// Test with large values
console.log(parseThreadId("9007199254740993"));
console.log(parseThreadId("99999999999999999999"));
```

## Remediation

1. Validate within safe range:
```typescript
function parseThreadId(id: string): number {
  const num = parseInt(id, 10);

  if (isNaN(num)) {
    throw new Error("Invalid thread ID");
  }

  if (num < 0 || num > Number.MAX_SAFE_INTEGER) {
    throw new Error("Thread ID out of range");
  }

  return num;
}
```

2. Use BigInt for large IDs:
```typescript
function parseThreadId(id: string): bigint {
  try {
    const num = BigInt(id);
    if (num < 0n) {
      throw new Error("Negative thread ID");
    }
    return num;
  } catch {
    throw new Error("Invalid thread ID");
  }
}
```

3. Keep as string if precision matters:
```typescript
function validateThreadId(id: string): string {
  if (!/^\d+$/.test(id)) {
    throw new Error("Invalid thread ID format");
  }
  if (id.length > 20) {
    throw new Error("Thread ID too long");
  }
  return id;
}
```

## References

- [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html)
