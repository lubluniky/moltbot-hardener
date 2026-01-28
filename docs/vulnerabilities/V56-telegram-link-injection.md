# V56: Telegram Link Injection

**Severity:** LOW
**Category:** Input Validation
**Auto-Fix:** No (requires code change)

## Description

Links in messages may contain `javascript:` or other dangerous protocols that could be rendered by Telegram clients.

## Affected Code

- `src/telegram/format.ts:23-34`

## Risk

- XSS via javascript: URLs
- Protocol handler abuse
- Phishing via custom protocols

## Attack Scenario

```typescript
// Malicious link in bot response
const message = "Click here: <a href=\"javascript:alert('XSS')\">Link</a>";

// Or using other protocols
const message = "Open this: <a href=\"file:///etc/passwd\">File</a>";
```

## Detection

```bash
# Check link handling
grep -r "buildTelegramLink\|<a href" src/telegram/
```

## Remediation

1. Validate link protocols:
```typescript
function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function buildTelegramLink(text: string, url: string): string {
  if (!isValidUrl(url)) {
    // Return text without link
    return escapeHtml(text);
  }
  return `<a href="${escapeHtmlAttr(url)}">${escapeHtml(text)}</a>`;
}
```

2. Sanitize with allowlist:
```typescript
const ALLOWED_PROTOCOLS = new Set(["http:", "https:", "tg:", "mailto:"]);

function sanitizeUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}
```

## References

- [CWE-79: Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)
