# V42: SSRF Redirect Bypass

**Severity:** MEDIUM
**Category:** Network
**Auto-Fix:** No (requires code change)

## Description

SSRF protection validates the initial URL but redirect targets may bypass checks. An attacker can use an open redirect to reach internal resources.

## Affected Code

- `src/media/input-files.ts:173-184`

## Risk

- Access to AWS metadata endpoint (169.254.169.254)
- Access to internal services
- Cloud credential theft
- Internal network scanning

## Attack Scenario

```
1. Attacker controls https://evil.com/redirect
2. evil.com redirects to http://169.254.169.254/latest/meta-data/
3. Initial URL passes SSRF check (evil.com is public)
4. Redirect bypasses check
5. AWS credentials leaked
```

## Detection

```bash
# Test with redirect
curl -v "https://gateway/fetch?url=https://httpbin.org/redirect-to?url=http://169.254.169.254/"
```

## Remediation

Re-validate each redirect target:

```typescript
async function fetchWithSsrfProtection(url: string, redirectCount = 0): Promise<Response> {
  if (redirectCount > 5) {
    throw new Error("Too many redirects");
  }

  // Validate URL against SSRF rules
  await validateNotPrivateIP(url);

  const response = await fetch(url, { redirect: "manual" });

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (location) {
      // Validate redirect target
      return fetchWithSsrfProtection(location, redirectCount + 1);
    }
  }

  return response;
}
```

## References

- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
