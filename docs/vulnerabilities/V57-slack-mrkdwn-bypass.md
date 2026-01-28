# V57: Slack Mrkdwn Token Bypass

**Severity:** LOW
**Category:** Input Validation
**Auto-Fix:** No (requires code change)

## Description

Slack markup token allowlist only validates the prefix, not the full token structure. Malformed tokens may bypass checks.

## Affected Code

- `src/slack/format.ts:13-26`

## Risk

- Mention injection
- Channel link injection
- Formatting exploitation

## Attack Scenario

```typescript
// Allowlist checks for <@, <#, <!
// But attacker uses:
const malicious = "<@|malicious payload>";

// Passes prefix check but contains injection
isAllowedSlackAngleToken("<@|malicious>")  // true (incorrectly)
```

## Detection

```bash
# Review token validation
grep -r "isAllowedSlackAngleToken" src/
```

## Remediation

1. Validate complete token structure:
```typescript
function isValidSlackMention(token: string): boolean {
  // User mention: <@U12345678>
  if (/^<@U[A-Z0-9]+>$/.test(token)) return true;

  // Channel mention: <#C12345678>
  if (/^<#C[A-Z0-9]+>$/.test(token)) return true;

  // Special mention: <!here>, <!channel>, <!everyone>
  if (/^<!(here|channel|everyone)>$/.test(token)) return true;

  return false;
}
```

2. Use strict regex:
```typescript
const SLACK_TOKEN_PATTERNS = [
  /^<@U[A-Z0-9]+(\|[^>]+)?>$/,      // User with optional label
  /^<#C[A-Z0-9]+(\|[^>]+)?>$/,      // Channel with optional label
  /^<!(here|channel|everyone)>$/,   // Special mentions
  /^<https?:\/\/[^|>]+(\|[^>]+)?>$/ // URLs
];

function isValidSlackToken(token: string): boolean {
  return SLACK_TOKEN_PATTERNS.some(p => p.test(token));
}
```

## References

- [Slack Message Formatting](https://api.slack.com/reference/surfaces/formatting)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
