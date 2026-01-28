# V28: Hook Token in Query Parameters

**Severity:** MEDIUM
**Category:** Authentication
**Auto-Fix:** No (requires code change)

## Description

Webhook endpoints accept authentication tokens via URL query parameters. Tokens in URLs are logged in server access logs, browser history, and referrer headers.

## Affected Code

- `src/gateway/hooks.ts:59-60` - `url.searchParams.get("token")`

## Risk

- Token exposure in server logs
- Token leakage via HTTP Referer header
- Token visible in browser history
- Shared URLs expose credentials

## Detection

```bash
# Check webhook configurations
moltbot config get hooks
# Look for token= in URLs
```

## Remediation

1. Use Authorization header instead of query params:
```http
Authorization: Bearer <token>
```

2. Disable query parameter token support:
```typescript
// Reject tokens from query params
if (url.searchParams.has("token")) {
  return { error: "Query param tokens disabled. Use Authorization header." };
}
```

3. Configure log sanitization to redact tokens

## References

- [OWASP: Session Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema)
