# V46: Gateway Lock File Predictable

**Severity:** MEDIUM
**Category:** Filesystem
**Auto-Fix:** No (requires code change)

## Description

The gateway lock file is created in `/tmp/moltbot-<uid>` which is a predictable location. A local attacker can pre-create this directory with restrictive permissions to cause a denial of service.

## Affected Code

- `src/config/paths.ts:175-180`

## Risk

- Local DoS by blocking gateway start
- Race condition exploitation
- Symlink attacks

## Attack Scenario

```bash
# As attacker (before victim starts gateway)
mkdir -p /tmp/moltbot-1000  # victim's UID
chmod 000 /tmp/moltbot-1000

# Victim tries to start gateway
moltbot gateway start
# Error: Cannot create lock file
```

## Detection

```bash
# Check lock directory ownership
ls -la /tmp/moltbot-$(id -u)/
```

## Remediation

1. Use user-private directory for locks:
```typescript
const LOCK_DIR = path.join(os.homedir(), ".clawdbot", "run");
await fs.mkdir(LOCK_DIR, { mode: 0o700, recursive: true });
```

2. Verify directory ownership before use:
```typescript
const stats = await fs.stat(lockDir);
if (stats.uid !== process.getuid()) {
  throw new Error("Lock directory owned by another user");
}
```

3. Create with exclusive flag:
```typescript
await fs.writeFile(lockFile, pid, { flag: "wx", mode: 0o600 });
```

## References

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
