# V24: Hooks Token Reuse

## Overview

| Property | Value |
|----------|-------|
| **ID** | V24 |
| **Severity** | Medium |
| **Category** | Gateway |
| **Auto-Fix** | Yes |
| **CVSS Score** | 5.4 |

## Description

The hooks token is the same as the gateway token, expanding the blast radius if either is compromised:

- Leaked hooks token = full gateway access
- Shared secret increases exposure surface

## Affected Files in Moltbot

- `src/security/audit-extra.ts` - Token reuse detection
- `src/hooks/config.ts` - Hooks configuration

## Detection

```go
func (c *HooksTokenCheck) Run(ctx *CheckContext) ([]Finding, error) {
    hooksToken := ctx.Config.Hooks.Token
    gatewayToken := ctx.Config.Gateway.Auth.Token

    if hooksToken != "" && hooksToken == gatewayToken {
        return []Finding{{
            CheckID:  "V24",
            Severity: SeverityMedium,
            Title:    "Hooks token reuses gateway token",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

Generate separate tokens:

```json
{
  "gateway": {
    "auth": {
      "token": "${CLAWDBOT_GATEWAY_TOKEN}"
    }
  },
  "hooks": {
    "token": "${CLAWDBOT_HOOKS_TOKEN}"
  }
}
```

## Manual Fix Instructions

```bash
# Generate separate hooks token
HOOKS_TOKEN=$(openssl rand -base64 32)
export CLAWDBOT_HOOKS_TOKEN="$HOOKS_TOKEN"

# Configure
moltbot config set hooks.token '${CLAWDBOT_HOOKS_TOKEN}'
```

## Verification Steps

```bash
# Tokens should be different
moltbot config get gateway.auth.token
moltbot config get hooks.token
```

## Related Vulnerabilities

- [V01: Gateway Exposure](V01-gateway-exposure.md)

## References

- [Moltbot Hooks Security](https://docs.molt.bot/gateway/security#hooks-hardening)
