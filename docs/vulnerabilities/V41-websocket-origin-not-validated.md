# V41: WebSocket Origin Not Validated

**Severity:** MEDIUM
**Category:** Network
**Auto-Fix:** No (requires code change)

## Description

The WebSocket server extracts the Origin header but only logs it without validation. This allows cross-origin WebSocket connections from malicious web pages (WebSocket CSRF).

## Affected Code

- `src/gateway/server/ws-connection.ts:73`

## Risk

- Cross-site WebSocket hijacking
- Malicious webpage can connect to local gateway
- Session hijacking via user's browser

## Attack Scenario

```html
<!-- evil-website.com -->
<script>
// Connect to victim's local gateway
const ws = new WebSocket("ws://localhost:18789/");
ws.onopen = () => {
  // Send commands as the user
  ws.send(JSON.stringify({ type: "invoke_tool", tool: "bash", cmd: "..." }));
};
</script>
```

## Detection

```typescript
// Check if origin validation exists
grep -r "verifyClient" src/gateway/
```

## Remediation

Add `verifyClient` callback to WebSocket server:

```typescript
const wss = new WebSocketServer({
  server: httpServer,
  verifyClient: (info, callback) => {
    const origin = info.origin || info.req.headers.origin;
    const allowedOrigins = ["http://localhost", "https://gateway.local"];

    if (origin && !allowedOrigins.includes(origin)) {
      callback(false, 403, "Origin not allowed");
      return;
    }

    callback(true);
  }
});
```

For development, allow localhost:
```typescript
if (origin?.startsWith("http://localhost")) {
  callback(true);
  return;
}
```

## References

- [WebSocket Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
