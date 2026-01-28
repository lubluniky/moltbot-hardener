# V45: Session Transcript Path Injection

**Severity:** MEDIUM
**Category:** Filesystem
**Auto-Fix:** No (requires code change)

## Description

The `topicId` parameter is used in file paths with `encodeURIComponent()` but this doesn't prevent all path traversal attacks when decoded elsewhere.

## Affected Code

- `src/config/sessions/paths.ts:41-49`

## Risk

- Path traversal to read/write arbitrary files
- Overwrite system files
- Read sensitive configuration

## Attack Scenario

```typescript
// Attacker controls topicId
const topicId = "..%2F..%2F..%2Fetc%2Fpasswd";
const path = resolveSessionTranscriptPath("session", "main", topicId);
// May resolve to /etc/passwd if decoded improperly later
```

## Detection

```bash
# Test with path traversal
moltbot session create --topic "../../etc/passwd"
```

## Remediation

1. Validate path containment after joining:
```typescript
function resolveSessionTranscriptPath(
  sessionId: string,
  agentId: string,
  topicId: string
): string {
  const baseDir = path.join(STATE_DIR, "sessions", sessionId, agentId);
  const fullPath = path.resolve(baseDir, encodeURIComponent(topicId));

  // Ensure path is within base directory
  if (!fullPath.startsWith(baseDir)) {
    throw new Error("Path traversal detected");
  }

  return fullPath;
}
```

2. Use allowlist for valid characters:
```typescript
const VALID_TOPIC_ID = /^[a-zA-Z0-9_-]+$/;
if (!VALID_TOPIC_ID.test(topicId)) {
  throw new Error("Invalid topic ID");
}
```

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
