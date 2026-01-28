# V32: Plugin Code No Verification

**Severity:** CRITICAL
**Category:** Plugins
**Auto-Fix:** No (requires code change)

## Description

Plugins are loaded via `jiti` (JavaScript/TypeScript dynamic import) without any code signing, hash verification, or integrity checks. Any installed plugin can execute arbitrary code with full Node.js access.

## Affected Code

- `src/plugins/loader.ts:294` - `jiti(candidate.source)`

## Risk

- Arbitrary code execution
- Full system access
- Credential theft
- Backdoor installation
- Supply chain attacks

## Attack Scenario

1. Attacker publishes malicious plugin to npm
2. User installs plugin: `moltbot plugin install malicious-plugin`
3. Plugin code executes with full permissions
4. Attacker has complete control of the system

## Detection

```bash
# List installed plugins
ls ~/.clawdbot/plugins/

# Check plugin source
cat ~/.clawdbot/plugins/*/package.json
```

## Remediation

1. Implement plugin signing:
```typescript
async function loadPlugin(path: string) {
  const manifest = await readManifest(path);
  const signature = await readSignature(path);

  if (!verifySignature(manifest, signature, TRUSTED_KEYS)) {
    throw new Error("Plugin signature verification failed");
  }

  return jiti(path);
}
```

2. Verify checksums before loading:
```typescript
const expectedHash = manifest.integrity;
const actualHash = computeHash(pluginCode);
if (expectedHash !== actualHash) {
  throw new Error("Plugin integrity check failed");
}
```

3. Run plugins in isolated V8 contexts or worker threads

## References

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
