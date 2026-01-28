# V54: Unbounded History Memory

**Severity:** MEDIUM
**Category:** Memory
**Auto-Fix:** No (requires code change)

## Description

Group chat history maps grow unboundedly across channels. An attacker flooding many channels can exhaust memory.

## Affected Code

- `src/auto-reply/reply/history.ts`

## Risk

- Memory exhaustion
- Out of memory crash
- Denial of service

## Attack Scenario

```bash
# Attacker sends messages to 100,000 different channels
# Each channel accumulates history in memory
# Server runs out of RAM
```

## Detection

```bash
# Monitor memory usage
ps aux | grep moltbot
watch -n1 'free -m'
```

## Remediation

1. Implement LRU cache:
```typescript
import LRU from "lru-cache";

const historyCache = new LRU<string, Message[]>({
  max: 1000,  // Max 1000 channels
  maxAge: 1000 * 60 * 60,  // 1 hour TTL
});
```

2. Limit history per channel:
```typescript
const MAX_HISTORY_PER_CHANNEL = 100;

function addToHistory(channelId: string, message: Message) {
  const history = historyCache.get(channelId) || [];
  history.push(message);

  if (history.length > MAX_HISTORY_PER_CHANNEL) {
    history.shift();  // Remove oldest
  }

  historyCache.set(channelId, history);
}
```

3. Periodic cleanup:
```typescript
setInterval(() => {
  const now = Date.now();
  for (const [key, history] of historyCache) {
    // Remove entries older than 1 hour
    const filtered = history.filter(m => now - m.timestamp < 3600000);
    if (filtered.length === 0) {
      historyCache.delete(key);
    } else {
      historyCache.set(key, filtered);
    }
  }
}, 60000);  // Every minute
```

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
