# V14: DM Scope Context Leak

## Overview

| Property | Value |
|----------|-------|
| **ID** | V14 |
| **Severity** | High |
| **Category** | Channels |
| **Auto-Fix** | Yes |
| **CVSS Score** | 7.1 |

## Description

Multiple users share the same DM session context (default `dmScope: "main"`), allowing:

- Cross-user conversation leakage
- One user seeing another's messages
- Context confusion
- Privacy violations

## Affected Files in Moltbot

- `src/config/types.ts` - Session scope settings
- `src/routing/session-key.ts` - Session key generation
- `src/security/audit.ts` - DM scope warnings

## Attack Scenario

1. **Multi-User Setup**: Multiple people can DM the bot
2. **Conversation**: User A asks about sensitive topic
3. **Context Leak**: User B's message gets context from User A's conversation
4. **Privacy Breach**: User B learns about User A's activities

### Example

```
User A: "Can you help me draft a resignation letter?"
Bot: "Sure, here's a draft..."

User B: "What were we talking about?"
Bot: "You were asking about drafting a resignation letter..."
```

## Detection

```go
func (c *DMScopeCheck) Run(ctx *CheckContext) ([]Finding, error) {
    dmScope := ctx.Config.Session.DMScope
    if dmScope == "" {
        dmScope = "main"
    }

    // Count allowed DM users across channels
    allowedUsers := c.countAllowedDMUsers(ctx.Config)

    if dmScope == "main" && allowedUsers > 1 {
        return []Finding{{
            CheckID:  "V14",
            Severity: SeverityHigh,
            Title:    "Multiple DM users share main session",
            Detail:   fmt.Sprintf("%d users can DM but dmScope='main'", allowedUsers),
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```json
{
  "session": {
    "dmScope": "per-channel-peer"
  }
}
```

For multi-account setups:

```json
{
  "session": {
    "dmScope": "per-account-channel-peer"
  }
}
```

## Manual Fix Instructions

### Per-Sender Sessions

```bash
moltbot config set session.dmScope per-channel-peer
```

### Per-Account-Sender Sessions

```bash
# For multi-account setups (multiple WhatsApp numbers, etc.)
moltbot config set session.dmScope per-account-channel-peer
```

### Link Known Identities

If the same person contacts you on multiple channels:

```json
{
  "session": {
    "dmScope": "per-channel-peer",
    "identityLinks": [
      {
        "canonical": "whatsapp:+1234567890",
        "aliases": ["telegram:@username", "signal:+1234567890"]
      }
    ]
  }
}
```

## Verification Steps

1. **Check DM scope**:
   ```bash
   moltbot config get session.dmScope
   # Should return: per-channel-peer
   ```

2. **Test isolation**:
   - Message from User A about specific topic
   - Message from User B asking "what did we discuss?"
   - User B should not see User A's context

3. **Check session keys**:
   ```bash
   # Sessions should have different keys per user
   ls ~/.moltbot/agents/main/sessions/*.jsonl
   ```

## DM Scope Options

| Scope | Isolation | Description |
|-------|-----------|-------------|
| `main` | None | All DMs share main session |
| `per-channel-peer` | Per-user | Each sender gets own session |
| `per-account-channel-peer` | Per-account-user | Isolated by account and user |

## Related Vulnerabilities

- [V02: DM Policy Open](V02-dm-policy-open.md)
- [V09: No Audit Logging](V09-no-audit-logging.md)

## References

- [Moltbot Session Management](https://docs.molt.bot/concepts/session)
- [DM Session Isolation](https://docs.molt.bot/gateway/security#dm-session-isolation)
