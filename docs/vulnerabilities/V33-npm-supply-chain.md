# V33: NPM Supply Chain Attack

**Severity:** CRITICAL
**Category:** Plugins
**Auto-Fix:** No (requires code change)

## Description

Plugin installation runs `npm install --omit=dev` which executes lifecycle scripts (preinstall, postinstall) from untrusted packages. Malicious packages can execute arbitrary code during installation.

## Affected Code

- `src/plugins/install.ts:170` - `npm install --omit=dev`
- `src/plugins/install.ts:357-360` - `npm pack` followed by extraction

## Risk

- Remote code execution during install
- No lockfile pinning
- Transitive dependency attacks
- Typosquatting attacks

## Attack Scenario

1. Attacker publishes package with malicious postinstall script
2. User installs plugin that depends on malicious package
3. `npm install` runs postinstall script
4. Attacker code executes before plugin even loads

## Detection

```bash
# Check for lifecycle scripts in plugins
find ~/.clawdbot/plugins -name "package.json" -exec grep -l "postinstall\|preinstall" {} \;
```

## Remediation

1. Use `--ignore-scripts` flag:
```typescript
await exec("npm", ["install", "--omit=dev", "--ignore-scripts"]);
```

2. Implement package allowlist:
```typescript
const ALLOWED_PACKAGES = new Set(["trusted-plugin-1", "trusted-plugin-2"]);

if (!ALLOWED_PACKAGES.has(packageName)) {
  throw new Error(`Package ${packageName} not in allowlist`);
}
```

3. Pin exact versions with integrity hashes:
```json
{
  "dependencies": {
    "plugin": "1.2.3",
    "integrity": "sha512-..."
  }
}
```

## References

- [npm Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
