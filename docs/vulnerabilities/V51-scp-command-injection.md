# V51: SCP Command Injection

**Severity:** HIGH
**Category:** Command Injection
**Auto-Fix:** No (requires code change)

## Description

Remote host and path for SCP are constructed without shell escaping. A malicious host or path can inject arbitrary commands.

## Affected Code

- `src/auto-reply/reply/stage-sandbox-media.ts:132-159`

## Risk

- Remote Code Execution (RCE)
- Complete system compromise
- Data exfiltration

## Attack Scenario

```typescript
// If remoteHost comes from user input
const remoteHost = "host; rm -rf /; echo ";
// Becomes: scp file.txt host; rm -rf /; echo :/path

// Or via path injection
const remotePath = "/path$(cat /etc/passwd > /tmp/pwned)";
```

## Detection

```bash
# Search for unescaped shell commands
grep -r "spawn.*scp" src/
grep -r "exec.*scp" src/
```

## Remediation

1. Use spawn with array arguments (no shell):
```typescript
import { spawn } from "child_process";

function scpFile(localPath: string, remoteHost: string, remotePath: string) {
  // Arguments as array - no shell interpolation
  const args = [localPath, `${remoteHost}:${remotePath}`];

  return new Promise((resolve, reject) => {
    const proc = spawn("scp", args, { shell: false });
    proc.on("exit", code => code === 0 ? resolve() : reject());
  });
}
```

2. Validate host format:
```typescript
const VALID_HOST = /^[a-zA-Z0-9.-]+$/;
if (!VALID_HOST.test(remoteHost)) {
  throw new Error("Invalid remote host");
}
```

3. Validate path format:
```typescript
const VALID_PATH = /^[a-zA-Z0-9/_.-]+$/;
if (!VALID_PATH.test(remotePath)) {
  throw new Error("Invalid remote path");
}
```

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
