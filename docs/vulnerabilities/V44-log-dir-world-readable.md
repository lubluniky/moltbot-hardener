# V44: Log Directory World-Readable

**Severity:** MEDIUM
**Category:** Filesystem
**Auto-Fix:** Partial

## Description

Logs are written to `/tmp/moltbot` which is world-readable on most Unix systems. Logs may contain sensitive information including user messages, API keys in errors, and session identifiers.

## Affected Code

- `src/logging/logger.ts:15-16`

## Affected Files

```
/tmp/moltbot/moltbot-*.log
```

## Risk

- Log file disclosure to local users
- Sensitive data exposure
- Session token leakage
- API key exposure in error messages

## Detection

```bash
# Check log directory permissions
ls -la /tmp/moltbot/

# Search for sensitive data in logs
grep -ri "token\|key\|password\|secret" /tmp/moltbot/
```

## Remediation

1. Store logs in user-private directory:
```typescript
const LOG_DIR = path.join(os.homedir(), ".clawdbot", "logs");
await fs.mkdir(LOG_DIR, { mode: 0o700, recursive: true });
```

2. Set restrictive permissions:
```bash
chmod 700 ~/.clawdbot/logs/
chmod 600 ~/.clawdbot/logs/*.log
```

3. Sanitize sensitive data before logging:
```typescript
function sanitizeForLog(obj: any): any {
  const sensitive = ["token", "key", "password", "secret"];
  return JSON.parse(JSON.stringify(obj, (k, v) =>
    sensitive.some(s => k.toLowerCase().includes(s)) ? "[REDACTED]" : v
  ));
}
```

## Quick Fix

```bash
# Move existing logs
mv /tmp/moltbot ~/.clawdbot/logs
chmod 700 ~/.clawdbot/logs
chmod 600 ~/.clawdbot/logs/*
```

## References

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
