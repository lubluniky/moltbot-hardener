# V01: Gateway Exposure

## Overview

| Property | Value |
|----------|-------|
| **ID** | V01 |
| **Severity** | Critical |
| **Category** | Gateway |
| **Auto-Fix** | Yes |
| **CVSS Score** | 9.8 |

## Description

The Moltbot gateway is bound to a network interface beyond loopback (localhost) without proper authentication configured. This exposes the gateway to the local network or potentially the internet, allowing unauthorized access to:

- Full agent control (send messages, execute tools)
- Session transcripts and history
- Configuration and credentials
- Browser control (if enabled)

## Affected Files in Moltbot

- `src/gateway/server-http.ts` - HTTP/WebSocket server binding
- `src/gateway/auth.ts` - Authentication resolution
- `src/config/types.gateway.ts` - Gateway configuration types
- `src/commands/doctor-security.ts` - Security warning generation

## Attack Scenario

1. **Reconnaissance**: Attacker scans local network for open port 18789
2. **Discovery**: Finds Moltbot gateway responding without auth
3. **Connection**: Opens WebSocket connection to gateway
4. **Exploitation**:
   - Sends messages to any connected channel
   - Executes shell commands via tools
   - Reads session transcripts
   - Accesses browser control
5. **Persistence**: Creates pairing codes for future access

### Attack Vector

```
Network -> Gateway:18789 -> No Auth -> Full Agent Control
```

### Example Attack

```javascript
// Attacker connects to exposed gateway
const ws = new WebSocket('ws://192.168.1.100:18789/ws');

ws.onopen = () => {
  // Execute arbitrary command
  ws.send(JSON.stringify({
    type: 'agent.message',
    payload: {
      message: 'Run: cat ~/.ssh/id_rsa',
      sessionKey: 'main'
    }
  }));
};
```

## Detection

The hardener detects this vulnerability by checking:

```go
func (c *GatewayExposureCheck) Run(ctx *CheckContext) ([]Finding, error) {
    bind := ctx.Config.Gateway.Bind
    if bind == "" {
        bind = "loopback"
    }

    isExposed := !isLoopback(bind)
    hasAuth := c.hasValidAuth(ctx.Config)

    if isExposed && !hasAuth {
        return []Finding{{
            CheckID:  "V01",
            Severity: SeverityCritical,
            Title:    "Gateway binds beyond loopback without auth",
        }}, nil
    }
    return nil, nil
}
```

## Fix Applied by Hardener

The hardener applies one of two fixes:

### Option 1: Bind to Loopback (Default)

```json
{
  "gateway": {
    "bind": "loopback"
  }
}
```

### Option 2: Generate Auth Token

```json
{
  "gateway": {
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "<generated-32-byte-random-token>"
    }
  }
}
```

## Manual Fix Instructions

### Option A: Restrict to Loopback

```bash
moltbot config set gateway.bind loopback
```

### Option B: Configure Authentication

```bash
# Generate a strong token
TOKEN=$(openssl rand -base64 32)

# Set token authentication
moltbot config set gateway.auth.mode token
moltbot config set gateway.auth.token "$TOKEN"

# Or use environment variable (recommended)
export CLAWDBOT_GATEWAY_TOKEN="$TOKEN"
moltbot config set gateway.auth.mode token
```

### Option C: Use Tailscale Serve

```bash
# Keep gateway on loopback, expose via Tailscale
moltbot config set gateway.bind loopback
moltbot config set gateway.tailscale.mode serve
```

## Verification Steps

1. **Check current binding**:
   ```bash
   moltbot config get gateway.bind
   # Should return: loopback
   ```

2. **Check auth configuration**:
   ```bash
   moltbot config get gateway.auth.mode
   # Should return: token (if bind is not loopback)
   ```

3. **Run security audit**:
   ```bash
   moltbot security audit --deep
   # Should not show "Gateway binds beyond loopback without auth"
   ```

4. **Test unauthorized access**:
   ```bash
   # Should fail if auth is required
   curl -s http://localhost:18789/health
   ```

5. **Verify with netstat**:
   ```bash
   # Should only show 127.0.0.1:18789, not 0.0.0.0:18789
   netstat -an | grep 18789
   ```

## Related Vulnerabilities

- [V20: Tailscale Funnel Exposure](V20-tailscale-funnel.md) - Public internet exposure
- [V23: Control UI Insecure Auth](V23-control-ui-insecure.md) - HTTP auth bypass

## References

- [Moltbot Security Documentation](https://docs.molt.bot/gateway/security)
- [Gateway Configuration](https://docs.molt.bot/gateway/configuration)
