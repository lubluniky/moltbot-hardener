# V69: Device Auth Store Unencrypted

**Severity:** LOW
**Category:** Credentials
**Auto-Fix:** No (requires code change)

## Description

Device authentication tokens are stored in plaintext JSON file with only file permission protection.

## Affected Code

- `src/infra/device-auth-store.ts`

## Affected Files

```
~/.clawdbot/identity/device-auth.json
```

## Risk

- Token theft if filesystem is compromised
- Device impersonation
- Persistent unauthorized access

## Detection

```bash
# Check for plaintext tokens
cat ~/.clawdbot/identity/device-auth.json | jq '.tokens'

# Check file permissions
ls -la ~/.clawdbot/identity/device-auth.json
```

## Remediation

1. Encrypt at rest:
```typescript
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

function encryptTokenStore(data: object, key: Buffer): Buffer {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data)),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]);
}
```

2. Use OS keychain:
```typescript
// macOS
import keytar from "keytar";
await keytar.setPassword("moltbot", "device-token", token);

// Linux
import SecretService from "secret-service";
await secretService.store("moltbot-device-token", token);
```

3. Derive key from machine identity:
```typescript
import { machineIdSync } from "node-machine-id";
import { pbkdf2Sync } from "crypto";

const machineId = machineIdSync();
const key = pbkdf2Sync(machineId, "moltbot-device-auth", 100000, 32, "sha256");
```

## Quick Fix

```bash
# At minimum, ensure correct permissions
chmod 600 ~/.clawdbot/identity/device-auth.json
chmod 700 ~/.clawdbot/identity/
```

## References

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
