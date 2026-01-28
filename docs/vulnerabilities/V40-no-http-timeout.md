# V40: No HTTP Request Timeout

**Severity:** MEDIUM
**Category:** Network
**Auto-Fix:** No (requires code change)

## Description

The HTTP server doesn't configure `headersTimeout`, `requestTimeout`, or `keepAliveTimeout`. This makes it vulnerable to slowloris attacks where attackers send partial requests slowly to tie up connections.

## Affected Code

- `src/gateway/server-http.ts`

## Risk

- Slowloris DoS attack
- Connection pool exhaustion
- Resource starvation

## Attack Scenario

```python
# Slowloris attack - send headers very slowly
import socket
import time

sock = socket.socket()
sock.connect(("gateway", 18789))
sock.send(b"GET / HTTP/1.1\r\n")
while True:
    sock.send(b"X-Header: ")
    time.sleep(10)  # Send 1 byte every 10 seconds
    sock.send(b"a")
```

## Detection

```bash
# Monitor for long-lived connections
netstat -an | grep 18789 | grep ESTABLISHED
```

## Remediation

Configure HTTP server timeouts:

```typescript
const httpServer = http.createServer(handler);

// Close connections with no complete headers after 60s
httpServer.headersTimeout = 60_000;

// Close connections with incomplete request after 5 min
httpServer.requestTimeout = 300_000;

// Close idle keep-alive connections after 5s
httpServer.keepAliveTimeout = 5_000;

// Limit max headers
httpServer.maxHeadersCount = 100;
```

## References

- [Slowloris Attack](https://en.wikipedia.org/wiki/Slowloris_(computer_security))
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
