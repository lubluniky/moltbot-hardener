# V70: Exec Approvals Token Cleartext

**Severity:** MEDIUM
**Category:** Credentials
**Auto-Fix:** No (requires code change)

## Description

The exec approvals socket token is stored in cleartext. This token grants command execution approval capabilities.

## Affected Code

- `src/infra/exec-approvals.ts:170-173, 224-232`

## Affected Files

```
~/.clawdbot/exec-approvals.json
```

## Risk

- Command execution approval bypass
- Unauthorized tool invocation
- Privilege escalation

## Detection

```bash
# View the token
cat ~/.clawdbot/exec-approvals.json | jq '.socket.token'

# Check permissions
ls -la ~/.clawdbot/exec-approvals.json
```

## Remediation

1. Use OS keychain for token:
```typescript
import keytar from "keytar";

async function getExecApprovalToken(): Promise<string> {
  let token = await keytar.getPassword("moltbot", "exec-approval-token");

  if (!token) {
    token = generateSecureToken();
    await keytar.setPassword("moltbot", "exec-approval-token", token);
  }

  return token;
}
```

2. Implement token rotation:
```typescript
const TOKEN_MAX_AGE_MS = 24 * 60 * 60 * 1000;  // 24 hours

async function getOrRotateToken(): Promise<string> {
  const stored = await loadToken();

  if (!stored || Date.now() - stored.createdAt > TOKEN_MAX_AGE_MS) {
    const newToken = generateSecureToken();
    await saveToken({ token: newToken, createdAt: Date.now() });
    return newToken;
  }

  return stored.token;
}
```

3. Encrypt the file:
```typescript
async function saveExecApprovals(data: ExecApprovals) {
  const key = await deriveKey();
  const encrypted = encrypt(JSON.stringify(data), key);
  await fs.writeFile(EXEC_APPROVALS_PATH, encrypted, { mode: 0o600 });
}
```

## Quick Fix

```bash
# Ensure correct permissions
chmod 600 ~/.clawdbot/exec-approvals.json

# Regenerate token (requires restart)
rm ~/.clawdbot/exec-approvals.json
moltbot gateway restart
```

## References

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
