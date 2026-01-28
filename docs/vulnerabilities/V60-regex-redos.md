# V60: Regex ReDoS in Mentions

**Severity:** LOW
**Category:** Denial of Service
**Auto-Fix:** No (requires code change)

## Description

User-provided mention patterns are compiled to regex without validation. Maliciously crafted patterns can cause catastrophic backtracking (ReDoS).

## Affected Code

- `src/auto-reply/reply/mentions.ts`

## Risk

- CPU exhaustion
- Request timeout
- Service unavailability

## Attack Scenario

```typescript
// Malicious pattern with catastrophic backtracking
const pattern = "(a+)+b";
const input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// This takes exponential time
new RegExp(pattern).test(input);
```

## Detection

```bash
# Check configured mention patterns
moltbot config get agent.mentionPatterns
```

## Remediation

1. Validate patterns against known ReDoS:
```typescript
import safeRegex from "safe-regex";

function validateMentionPattern(pattern: string): boolean {
  if (!safeRegex(pattern)) {
    throw new Error("Potentially dangerous regex pattern");
  }
  return true;
}
```

2. Add timeout wrapper:
```typescript
function matchWithTimeout(
  pattern: RegExp,
  input: string,
  timeoutMs: number
): boolean {
  const start = Date.now();

  // Use a worker or async approach with timeout
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Regex timeout"));
    }, timeoutMs);

    try {
      const result = pattern.test(input);
      clearTimeout(timeout);
      resolve(result);
    } catch (e) {
      clearTimeout(timeout);
      reject(e);
    }
  });
}
```

3. Limit pattern complexity:
```typescript
function validatePattern(pattern: string) {
  // No nested quantifiers
  if (/(\+|\*|\?)\s*(\+|\*|\?)/.test(pattern)) {
    throw new Error("Nested quantifiers not allowed");
  }

  // Max length
  if (pattern.length > 100) {
    throw new Error("Pattern too long");
  }
}
```

## References

- [ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
