# V39: No WebSocket Rate Limiting

**Severity:** MEDIUM
**Category:** Network
**Auto-Fix:** No (requires code change)

## Description

The WebSocket server has no limit on connections per IP address. An attacker can exhaust server resources by opening many simultaneous connections.

## Affected Code

- `src/gateway/server-runtime-state.ts`

## Risk

- Denial of Service via connection exhaustion
- Memory exhaustion
- CPU exhaustion from handshake processing
- File descriptor exhaustion

## Attack Scenario

```bash
# Open 10000 connections from single IP
for i in $(seq 1 10000); do
  websocat ws://gateway:18789/ &
done
```

## Detection

```bash
# Check current connections
ss -s | grep ESTAB
netstat -an | grep 18789 | wc -l
```

## Remediation

1. Add per-IP connection rate limiting:
```typescript
const connectionCounts = new Map<string, number>();
const MAX_CONNECTIONS_PER_IP = 100;

wss.on("connection", (ws, req) => {
  const ip = req.socket.remoteAddress;
  const count = connectionCounts.get(ip) || 0;

  if (count >= MAX_CONNECTIONS_PER_IP) {
    ws.close(1008, "Too many connections");
    return;
  }

  connectionCounts.set(ip, count + 1);
  ws.on("close", () => {
    connectionCounts.set(ip, (connectionCounts.get(ip) || 1) - 1);
  });
});
```

2. Implement connection queue with backpressure

3. Add total connection limit:
```typescript
const MAX_TOTAL_CONNECTIONS = 10000;
```

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
