# V10: Weak Pairing Codes

## Overview

| Property | Value |
|----------|-------|
| **ID** | V10 |
| **Severity** | Medium |
| **Category** | Channels |
| **Auto-Fix** | Yes |
| **CVSS Score** | 5.9 |

## Description

Pairing code configuration is weak, allowing potential brute-force or enumeration attacks:

- Short pairing codes (easily guessable)
- Long expiration times
- No rate limiting on pairing attempts
- Too many pending requests allowed

## Affected Files in Moltbot

- `src/pairing/pairing-store.ts` - Pairing code generation
- `src/pairing/pairing-messages.ts` - Pairing message handling
- `src/channels/plugins/pairing.ts` - Channel pairing integration

## Attack Scenario

1. **Probe**: Attacker sends DM to bot, receives pairing code
2. **Brute Force**: If codes are short, attacker enumerates possibilities
3. **Or**: Attacker creates many pending requests (resource exhaustion)
4. **Access**: If successful, attacker is added to allowlist

## Detection

```go
func (c *WeakPairingCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    // Check default pairing settings
    // Note: These are typically hardcoded but can be overridden

    return findings, nil
}
```

## Fix Applied by Hardener

The hardener ensures pairing is properly configured with reasonable defaults:

```json
{
  "channels": {
    "defaults": {
      "pairing": {
        "codeLength": 6,
        "expirationMinutes": 60,
        "maxPending": 3
      }
    }
  }
}
```

## Manual Fix Instructions

### Verify Pairing Settings

Moltbot uses secure defaults:
- 6-character alphanumeric codes
- 1-hour expiration
- Maximum 3 pending requests per channel

### Monitor Pending Requests

```bash
# Check pending pairing requests
moltbot pairing list whatsapp
moltbot pairing list telegram
```

### Manually Approve/Deny

```bash
# Approve known user
moltbot pairing approve whatsapp <code>

# Clear pending requests
moltbot pairing clear whatsapp
```

## Verification Steps

1. **Test pairing flow**:
   - Send DM from unknown number
   - Verify 6-character code is generated
   - Verify code expires after 1 hour

2. **Test rate limiting**:
   - Send multiple DMs from different numbers
   - Verify only 3 pending requests allowed

3. **Check pending count**:
   ```bash
   moltbot pairing list whatsapp | wc -l
   # Should be <= 3
   ```

## Related Vulnerabilities

- [V02: DM Policy Open](V02-dm-policy-open.md)
- [V15: Pairing DoS](V15-pairing-dos.md)

## References

- [Moltbot Pairing Documentation](https://docs.molt.bot/start/pairing)
