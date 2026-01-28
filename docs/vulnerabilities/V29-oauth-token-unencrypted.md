# V29: OAuth Refresh Token Unencrypted

**Severity:** MEDIUM
**Category:** Credentials
**Auto-Fix:** No (requires code change)

## Description

OAuth refresh tokens are stored in plaintext JSON files. Refresh tokens are long-lived and can be used to obtain new access tokens without user interaction.

## Affected Code

- `src/agents/auth-profiles/store.ts` - stores tokens in `auth-profiles.json`

## Affected Files

```
~/.clawdbot/auth-profiles.json
```

## Risk

- Refresh token theft if filesystem is compromised
- Long-term unauthorized access to OAuth-protected resources
- No token rotation on file access

## Detection

```bash
# Check for plaintext tokens
cat ~/.clawdbot/auth-profiles.json | jq '.profiles[].refreshToken'
```

## Remediation

1. Use OS-level secure storage:
   - macOS: Keychain
   - Linux: Secret Service / libsecret
   - Windows: Credential Manager

2. Implement at-rest encryption:
```typescript
import { createCipheriv, createDecipheriv } from 'crypto';

function encryptToken(token: string, key: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  // ...
}
```

3. Restrict file permissions:
```bash
chmod 600 ~/.clawdbot/auth-profiles.json
```

## References

- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
