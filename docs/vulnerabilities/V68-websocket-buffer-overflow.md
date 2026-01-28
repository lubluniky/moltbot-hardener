# V68: WebSocket Buffer Overflow

**Severity:** LOW
**Category:** Memory
**Auto-Fix:** No (requires code change)

## Description

Slow clients accumulate unbounded message buffers. The `MAX_BUFFERED_BYTES` limit exists but may not prevent memory growth with many slow clients.

## Affected Code

- `src/gateway/server-constants.ts:2`
- `MAX_BUFFERED_BYTES = 1.5 * 1024 * 1024`

## Risk

- Memory exhaustion
- Service degradation
- Denial of service

## Attack Scenario

```python
# Slow client attack
import websocket
import time

ws = websocket.create_connection("ws://gateway:18789/")
# Don't read messages, let buffer grow
while True:
    time.sleep(1)  # Just keep connection alive
# Server buffers grow until OOM
```

## Detection

```bash
# Monitor memory
watch -n1 'ps aux | grep moltbot | grep -v grep'

# Check WebSocket connections
ss -s | grep ESTAB
```

## Remediation

1. Strict per-connection limits:
```typescript
const MAX_BUFFERED_BYTES_PER_CLIENT = 1024 * 1024;  // 1MB

ws.on("message", (data) => {
  if (ws.bufferedAmount > MAX_BUFFERED_BYTES_PER_CLIENT) {
    log.warn("Client buffer full, dropping message");
    return;  // Drop message
  }
  // Process message
});
```

2. Terminate slow clients:
```typescript
setInterval(() => {
  for (const client of wss.clients) {
    if (client.bufferedAmount > MAX_BUFFERED_BYTES_PER_CLIENT) {
      log.warn("Terminating slow client");
      client.terminate();
    }
  }
}, 5000);
```

3. Use backpressure:
```typescript
async function sendToClient(client: WebSocket, data: any) {
  if (client.bufferedAmount > BACKPRESSURE_THRESHOLD) {
    await waitForDrain(client);
  }
  client.send(JSON.stringify(data));
}
```

4. Track dropped messages:
```typescript
const droppedMessages = new Counter("dropped_messages_total");
```

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
