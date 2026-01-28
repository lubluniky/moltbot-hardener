# V47: Config Backup Exposes Old Secrets

**Severity:** LOW
**Category:** Filesystem
**Auto-Fix:** Partial

## Description

Config backups (`.bak.1` through `.bak.4`) may contain API keys or tokens that have since been rotated. These historical secrets remain accessible.

## Affected Code

- `src/config/io.ts:91-106`

## Affected Files

```
~/.clawdbot/config.yaml.bak.1
~/.clawdbot/config.yaml.bak.2
~/.clawdbot/config.yaml.bak.3
~/.clawdbot/config.yaml.bak.4
```

## Risk

- Historical credential exposure
- Rotated keys still usable
- Backup files may have weaker permissions

## Detection

```bash
# List backup files
ls -la ~/.clawdbot/*.bak*

# Check for secrets
grep -ri "token\|key\|secret" ~/.clawdbot/*.bak*
```

## Remediation

1. Encrypt backup files:
```typescript
async function createBackup(configPath: string) {
  const content = await fs.readFile(configPath);
  const encrypted = await encrypt(content, BACKUP_KEY);
  await fs.writeFile(`${configPath}.bak`, encrypted, { mode: 0o600 });
}
```

2. Reduce retention:
```typescript
const MAX_BACKUPS = 2;  // Instead of 4
```

3. Set consistent permissions:
```bash
chmod 600 ~/.clawdbot/*.bak*
```

4. Scrub secrets from backups:
```typescript
function scrubSecrets(config: Config): Config {
  return {
    ...config,
    apiKey: "[REDACTED]",
    tokens: {}
  };
}
```

## Quick Fix

```bash
# Remove old backups
rm ~/.clawdbot/*.bak.*

# Or set permissions
chmod 600 ~/.clawdbot/*.bak*
```

## References

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
