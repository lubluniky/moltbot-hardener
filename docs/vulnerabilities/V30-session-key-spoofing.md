# V30: Session Key Spoofing

**Severity:** HIGH
**Category:** Authorization
**Auto-Fix:** No (requires code change)

## Description

The `/tools/invoke` endpoint accepts a `sessionKey` parameter in the request body without verifying that the authenticated client has permission to access that session.

## Affected Code

- `src/gateway/tools-invoke-http.ts:115-117` - `body.sessionKey` used without ownership check

## Attack Scenario

1. Attacker authenticates with valid credentials
2. Attacker guesses or obtains another user's session key
3. Attacker invokes tools in victim's session context
4. Tools execute with victim's permissions and context

## Risk

- Cross-user tool execution
- Data access across session boundaries
- Privilege escalation

## Detection

```bash
# Test with another session's key
curl -X POST https://gateway/tools/invoke \
  -H "Authorization: Bearer $MY_TOKEN" \
  -d '{"sessionKey": "victim-session-key", "tool": "read_file", "params": {...}}'
```

## Remediation

Validate session ownership before allowing tool invocation:

```typescript
async function handleToolsInvoke(req: Request) {
  const client = authenticateRequest(req);
  const { sessionKey, tool, params } = req.body;

  // Verify ownership
  if (!client.canAccessSession(sessionKey)) {
    return { error: "Session access denied" };
  }

  // Proceed with tool invocation
}
```

## References

- [CWE-639: Authorization Bypass](https://cwe.mitre.org/data/definitions/639.html)
