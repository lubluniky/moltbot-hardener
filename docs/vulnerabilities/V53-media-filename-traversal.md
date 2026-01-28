# V53: Media Filename Path Traversal

**Severity:** LOW
**Category:** Filesystem
**Auto-Fix:** No (requires code change)

## Description

Content-Disposition filename from HTTP headers may contain traversal sequences. While `path.basename()` provides some protection, edge cases with encoded characters may slip through.

## Affected Code

- `src/media/fetch.ts:36-51`

## Risk

- Write files outside intended directory
- Overwrite sensitive files
- Code execution via file placement

## Attack Scenario

```http
Content-Disposition: attachment; filename*=UTF-8''..%2F..%2Fetc%2Fcron.d%2Fmalicious
```

## Detection

```bash
# Check for filename sanitization
grep -r "Content-Disposition" src/
grep -r "parseContentDisposition" src/
```

## Remediation

1. Apply sanitization consistently:
```typescript
function sanitizeFilename(filename: string): string {
  // Remove path separators
  let safe = path.basename(filename);

  // Remove dangerous characters
  safe = safe.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_");

  // Prevent hidden files
  if (safe.startsWith(".")) {
    safe = "_" + safe;
  }

  // Limit length
  if (safe.length > 255) {
    const ext = path.extname(safe);
    safe = safe.slice(0, 255 - ext.length) + ext;
  }

  return safe || "unnamed";
}
```

2. Validate final path:
```typescript
const finalPath = path.join(mediaDir, sanitizeFilename(filename));
if (!finalPath.startsWith(mediaDir)) {
  throw new Error("Path traversal detected");
}
```

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
