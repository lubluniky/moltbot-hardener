# V52: Forwarded Message Spoofing

**Severity:** MEDIUM
**Category:** Message Handling
**Auto-Fix:** No (requires code change)

## Description

Discord forwarded message author attribution is derived from untrusted snapshot data. An attacker could craft messages with spoofed author information.

## Affected Code

- `src/discord/monitor/message-utils.ts:211-226`

## Risk

- Impersonation of other users
- Social engineering attacks
- Fake admin messages
- Trust exploitation

## Attack Scenario

```typescript
// Attacker crafts message with fake snapshot
const message = {
  message_snapshots: [{
    message: {
      author: {
        global_name: "Admin",
        username: "real_admin"
      },
      content: "Please send me your API key"
    }
  }]
};
// Bot shows: "Forwarded from Admin: Please send me your API key"
```

## Detection

```bash
# Review forwarded message handling
grep -r "message_snapshots" src/
grep -r "formatDiscordSnapshotAuthor" src/
```

## Remediation

1. Sanitize snapshot author fields:
```typescript
function formatForwardedAuthor(snapshot: MessageSnapshot): string {
  const author = snapshot.message?.author;
  if (!author) return "[Unknown]";

  // Sanitize to prevent injection
  const name = sanitize(author.global_name || author.username);
  return `[Forwarded from ${name}]`;
}

function sanitize(str: string): string {
  return str.replace(/[<>@#]/g, "").slice(0, 32);
}
```

2. Mark forwarded content explicitly as untrusted:
```typescript
const content = `⚠️ FORWARDED (unverified): ${forwardedContent}`;
```

3. Add visual distinction:
```typescript
// Use different formatting for forwarded messages
const embed = {
  author: { name: "Forwarded Message (unverified)" },
  description: forwardedContent,
  color: 0x888888  // Gray to indicate untrusted
};
```

## References

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
