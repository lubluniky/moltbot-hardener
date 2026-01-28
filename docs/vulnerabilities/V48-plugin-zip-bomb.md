# V48: Plugin Archive Zip Bomb

**Severity:** MEDIUM
**Category:** Plugins
**Auto-Fix:** No (requires code change)

## Description

Plugin archive extraction has no size limit. A malicious plugin archive (zip bomb) could expand to fill the entire disk.

## Affected Code

- `src/plugins/install.ts`
- `src/infra/archive.ts`

## Risk

- Disk space exhaustion
- Denial of service
- System instability

## Attack Scenario

```bash
# Create a zip bomb (42.zip expands to 4.5 PB)
# Or create modest bomb: 10MB compressed → 10GB extracted
moltbot plugin install ./bomb-plugin.tgz
# Disk fills up, system crashes
```

## Detection

```bash
# Check plugin sizes
du -sh ~/.clawdbot/plugins/*

# Monitor during install
watch -n1 'df -h /'
```

## Remediation

1. Track decompressed size during extraction:
```typescript
async function extractWithLimit(archive: string, dest: string, maxBytes: number) {
  let totalBytes = 0;

  for await (const entry of tar.extract(archive)) {
    totalBytes += entry.size;

    if (totalBytes > maxBytes) {
      throw new Error(`Archive exceeds ${maxBytes} byte limit`);
    }

    await writeEntry(entry, dest);
  }
}
```

2. Check manifest before extraction:
```typescript
const manifest = await readManifestFromArchive(archive);
if (manifest.uncompressedSize > MAX_PLUGIN_SIZE) {
  throw new Error("Plugin too large");
}
```

3. Set reasonable limits:
```typescript
const MAX_PLUGIN_SIZE = 100 * 1024 * 1024;  // 100MB
const MAX_PLUGIN_FILES = 10000;
```

## References

- [Zip Bomb](https://en.wikipedia.org/wiki/Zip_bomb)
- [CWE-409: Improper Handling of Highly Compressed Data](https://cwe.mitre.org/data/definitions/409.html)
