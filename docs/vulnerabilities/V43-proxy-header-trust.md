# V43: Proxy Header Trust Issues

**Severity:** MEDIUM
**Category:** Network
**Auto-Fix:** No (requires code change)

## Description

Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are trusted without strict IP validation. Simple string matching may miss address normalization cases.

## Affected Code

- `src/gateway/auth.ts:68-104` - `isLocalDirectRequest`
- `src/gateway/net.ts:51-55` - `isTrustedProxyAddress`

## Risk

- IP spoofing via forged headers
- Bypass IP-based access controls
- Incorrect client identification
- Log poisoning

## Attack Scenario

```bash
# Attacker bypasses IP check
curl -H "X-Forwarded-For: 127.0.0.1" https://gateway/admin/
```

## Detection

```bash
# Check trusted proxy configuration
moltbot config get gateway.trustedProxies
```

## Remediation

1. Use canonical IP comparison:
```typescript
import { isIP } from 'net';

function normalizeIP(ip: string): string {
  // Handle IPv6 compressed forms
  if (isIP(ip) === 6) {
    return new URL(`http://[${ip}]`).hostname;
  }
  return ip;
}

function isTrustedProxy(ip: string, trusted: string[]): boolean {
  const normalizedIp = normalizeIP(ip);
  return trusted.some(t => normalizeIP(t) === normalizedIp);
}
```

2. Log spoofing attempts:
```typescript
if (headers["x-forwarded-for"] && !isTrustedProxy(remoteIp)) {
  log.warn("Untrusted source sent proxy headers", { remoteIp });
}
```

3. Reject proxy headers from non-proxies:
```typescript
if (!isTrustedProxy(remoteIp)) {
  delete headers["x-forwarded-for"];
  delete headers["x-real-ip"];
}
```

## References

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
