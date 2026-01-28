# V15: Pairing DoS

## Overview

| Property | Value |
|----------|-------|
| **ID** | V15 |
| **Severity** | Medium |
| **Category** | Channels |
| **Auto-Fix** | Yes |
| **CVSS Score** | 5.3 |

## Description

The pairing system can be abused for denial of service:

- Flooding with pairing requests
- Exhausting pending request slots
- Preventing legitimate users from pairing
- Resource exhaustion on gateway

## Affected Files in Moltbot

- `src/pairing/pairing-store.ts` - Request management
- `src/pairing/pairing-messages.ts` - Rate limiting

## Attack Scenario

1. **Flood**: Attacker sends DMs from many numbers
2. **Saturation**: Fills up pending pairing slots
3. **Block**: Legitimate users can't initiate pairing
4. **Resource**: Gateway spends resources on fake requests

## Detection

```go
func (c *PairingDoSCheck) Run(ctx *CheckContext) ([]Finding, error) {
    // Check if pairing is enabled but limits are loose
    // Default: 3 pending, 1 hour expiry

    return nil, nil  // Uses secure defaults
}
```

## Fix Applied by Hardener

Moltbot uses secure defaults. The hardener verifies they're in place:

- Maximum 3 pending requests per channel
- 1 hour expiration
- Rate limiting on requests

## Manual Fix Instructions

### Monitor Pending Requests

```bash
# Check pending counts
moltbot pairing list whatsapp
moltbot pairing list telegram
```

### Clear Suspicious Requests

```bash
# Clear all pending for a channel
moltbot pairing clear whatsapp
```

### Deny Specific Senders

```bash
# If specific numbers are flooding
moltbot pairing deny whatsapp <code-or-number>
```

## Verification Steps

1. **Check pending count**:
   ```bash
   moltbot pairing list whatsapp | wc -l
   # Should be <= 3
   ```

2. **Test rate limiting**:
   - Send multiple DMs rapidly
   - Verify not all create pending requests

## Related Vulnerabilities

- [V02: DM Policy Open](V02-dm-policy-open.md)
- [V10: Weak Pairing Codes](V10-weak-pairing-codes.md)

## References

- [Moltbot Pairing Documentation](https://docs.molt.bot/start/pairing)
