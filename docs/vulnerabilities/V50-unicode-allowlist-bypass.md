# V50: Unicode Bypass in Allowlists

**Severity:** MEDIUM
**Category:** Authentication
**Auto-Fix:** No (requires code change)

## Description

Username allowlist comparison doesn't account for Unicode confusables. Visually identical characters from different scripts can bypass allowlist checks.

## Affected Code

- `src/telegram/bot-access.ts`
- `src/discord/monitor/allow-list.ts`

## Examples

| Allowed | Attacker Uses | Looks Like |
|---------|---------------|------------|
| `admin` | `аdmin` (Cyrillic а) | admin |
| `alice` | `аlice` (Cyrillic а) | alice |
| `bob` | `bоb` (Cyrillic о) | bob |

## Risk

- Allowlist bypass via homoglyph attack
- Impersonation of allowed users
- Unauthorized access

## Attack Scenario

```python
# Attacker creates username with Cyrillic characters
username = "аdmin"  # First char is Cyrillic 'а' (U+0430)

# Looks identical to "admin" (Latin 'a' U+0061)
# But string comparison fails: "admin" !== "аdmin"
```

## Detection

```bash
# Check for non-ASCII in allowlist entries
moltbot config get dmPolicy.allowlist | od -c | grep -v "^[a-zA-Z0-9]"
```

## Remediation

1. Apply Unicode normalization:
```typescript
import { normalize } from "unorm";

function normalizeUsername(name: string): string {
  // NFC normalization
  return normalize.nfc(name).toLowerCase();
}
```

2. Use confusable detection:
```typescript
import confusables from "confusables";

function checkAllowlist(username: string, allowlist: string[]): boolean {
  const skeleton = confusables.skeleton(username);
  return allowlist.some(allowed =>
    confusables.skeleton(allowed) === skeleton
  );
}
```

3. Restrict to ASCII only:
```typescript
const ASCII_ONLY = /^[a-zA-Z0-9_]+$/;
if (!ASCII_ONLY.test(username)) {
  throw new Error("Username must be ASCII only");
}
```

## References

- [Unicode Security Guide](https://unicode.org/reports/tr36/)
- [CWE-1007: Insufficient Visual Distinction of Homoglyphs](https://cwe.mitre.org/data/definitions/1007.html)
