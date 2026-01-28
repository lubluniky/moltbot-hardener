# V55: Sticker Cache No Size Limit

**Severity:** LOW
**Category:** Memory/Disk
**Auto-Fix:** No (requires code change)

## Description

Telegram sticker cache grows without bounds. Receiving many unique stickers causes the cache to grow indefinitely.

## Affected Code

- `src/telegram/sticker-cache.ts`

## Affected Files

```
~/.clawdbot/telegram/sticker-cache.json
```

## Risk

- Disk space exhaustion
- Slow cache operations
- Memory pressure during load

## Detection

```bash
# Check cache size
wc -c ~/.clawdbot/telegram/sticker-cache.json
du -sh ~/.clawdbot/telegram/
```

## Remediation

1. Add LRU eviction:
```typescript
const MAX_STICKERS = 10000;

function addToStickerCache(stickerId: string, description: string) {
  cache.set(stickerId, {
    description,
    lastUsed: Date.now()
  });

  if (cache.size > MAX_STICKERS) {
    evictOldest();
  }
}

function evictOldest() {
  let oldest = { id: "", time: Infinity };
  for (const [id, entry] of cache) {
    if (entry.lastUsed < oldest.time) {
      oldest = { id, time: entry.lastUsed };
    }
  }
  cache.delete(oldest.id);
}
```

2. Add periodic pruning:
```typescript
setInterval(() => {
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;  // 7 days
  for (const [id, entry] of cache) {
    if (entry.lastUsed < cutoff) {
      cache.delete(id);
    }
  }
  saveCache();
}, 24 * 60 * 60 * 1000);  // Daily
```

## Quick Fix

```bash
# Manually clear cache if too large
rm ~/.clawdbot/telegram/sticker-cache.json
```

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
