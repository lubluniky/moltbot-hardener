# V62: DNS Rebinding via SSRF

**Severity:** MEDIUM
**Category:** Network
**Auto-Fix:** No (requires code change)

## Description

DNS re-resolution may return different IP addresses after the initial SSRF check, allowing attackers to access internal resources via DNS rebinding.

## Affected Code

- `src/infra/net/ssrf.ts`

## Risk

- SSRF via DNS rebinding
- Access to internal services
- Cloud metadata exposure
- Internal network scanning

## Attack Scenario

```
1. Attacker controls evil.com DNS
2. First DNS lookup: evil.com → 1.2.3.4 (public IP, passes check)
3. HTTP request initiated to evil.com
4. DNS TTL expires during request
5. Second lookup: evil.com → 169.254.169.254 (AWS metadata)
6. Request reaches internal service
```

## Detection

```bash
# Test with DNS rebinding service
curl "http://gateway/fetch?url=http://rebind.attacker.com/"
```

## Remediation

1. Pin DNS resolution:
```typescript
import { lookup } from "dns/promises";

async function fetchWithPinnedDns(url: string): Promise<Response> {
  const parsed = new URL(url);
  const { address } = await lookup(parsed.hostname);

  // Validate resolved IP
  if (isPrivateIP(address)) {
    throw new Error("Private IP not allowed");
  }

  // Use resolved IP for request
  const pinnedUrl = new URL(url);
  pinnedUrl.hostname = address;

  return fetch(pinnedUrl, {
    headers: { Host: parsed.hostname }
  });
}
```

2. Validate on connection:
```typescript
import { Agent } from "https";

const agent = new Agent({
  lookup: (hostname, options, callback) => {
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) return callback(err);

      if (isPrivateIP(address)) {
        return callback(new Error("Private IP blocked"));
      }

      callback(null, address, family);
    });
  }
});
```

3. Disable redirects or re-validate:
```typescript
const response = await fetch(url, { redirect: "manual" });
if (response.status >= 300 && response.status < 400) {
  const location = response.headers.get("location");
  // Re-validate the redirect target
  await validateUrl(location);
}
```

## References

- [DNS Rebinding](https://en.wikipedia.org/wiki/DNS_rebinding)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
