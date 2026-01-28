# V61: Thread Starter Context Leak

**Severity:** LOW
**Category:** Information Disclosure
**Auto-Fix:** No (requires code change)

## Description

Thread starter cache may serve stale data across sessions, potentially leaking thread context from one conversation to another.

## Affected Code

- `src/slack/monitor/message-handler/prepare.ts:454-491`

## Risk

- Cross-session context leakage
- Privacy violation
- Conversation mixing

## Attack Scenario

```
1. User A starts thread about confidential topic
2. Thread starter cached with thread ID
3. User B creates thread with same timestamp (different channel)
4. Cache returns User A's thread starter
5. Context leak occurs
```

## Detection

```bash
# Check for thread starter caching
grep -r "ThreadStarterBody" src/
grep -r "threadStarter" src/
```

## Remediation

1. Include session key in cache key:
```typescript
function getThreadStarterCacheKey(
  sessionKey: string,
  channelId: string,
  threadTs: string
): string {
  return `${sessionKey}:${channelId}:${threadTs}`;
}
```

2. Validate session ownership:
```typescript
async function getThreadStarter(
  sessionKey: string,
  channelId: string,
  threadTs: string
): Promise<ThreadStarter | null> {
  const cached = cache.get(getCacheKey(sessionKey, channelId, threadTs));

  if (cached && cached.sessionKey !== sessionKey) {
    // Wrong session, ignore cache
    return null;
  }

  return cached;
}
```

3. Add TTL to cache entries:
```typescript
const cache = new LRU<string, ThreadStarter>({
  max: 1000,
  maxAge: 1000 * 60 * 60  // 1 hour
});
```

## References

- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
