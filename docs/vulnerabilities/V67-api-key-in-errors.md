# V67: API Key in Error Messages

**Severity:** LOW
**Category:** Information Disclosure
**Auto-Fix:** No (requires code change)

## Description

OAuth and API errors may expose credential fragments in error messages and logs.

## Affected Code

- `src/agents/auth-profiles/oauth.ts:225-236`

## Risk

- Partial credential exposure
- API key fragments in logs
- Information leakage to users

## Detection

```bash
# Search logs for potential credential exposure
grep -i "key\|token\|secret\|auth" ~/.clawdbot/logs/*.log | grep -i "error\|fail"
```

## Remediation

1. Sanitize error messages:
```typescript
function sanitizeError(error: Error): Error {
  let message = error.message;

  // Remove potential credentials
  message = message.replace(/[a-zA-Z0-9]{20,}/g, "[REDACTED]");
  message = message.replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]");
  message = message.replace(/api[_-]?key[=:]\s*\S+/gi, "api_key=[REDACTED]");

  return new Error(message);
}
```

2. Use error codes instead of details:
```typescript
const ERROR_CODES = {
  AUTH_FAILED: "Authentication failed",
  TOKEN_EXPIRED: "Token expired",
  INVALID_CREDENTIALS: "Invalid credentials"
};

throw new Error(ERROR_CODES.AUTH_FAILED);
// Instead of: throw new Error(`Auth failed with key ${apiKey.slice(0,5)}...`);
```

3. Separate user-facing and internal errors:
```typescript
class UserFacingError extends Error {
  constructor(
    public userMessage: string,
    public internalDetails: string
  ) {
    super(userMessage);
  }
}

// Log internal details, show user message
catch (e) {
  if (e instanceof UserFacingError) {
    log.error("Internal:", e.internalDetails);
    return { error: e.userMessage };
  }
}
```

## References

- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
