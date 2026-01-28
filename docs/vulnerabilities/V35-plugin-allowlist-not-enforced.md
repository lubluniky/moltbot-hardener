# V35: Plugin Allowlist Not Enforced

**Severity:** HIGH
**Category:** Plugins
**Auto-Fix:** No (requires code change)

## Description

The `plugins.allow` configuration option only triggers a warning in security audit but doesn't actually block loading of unlisted plugins.

## Affected Code

- `src/plugins/loader.ts:252-276` - `resolveEnableState` doesn't check allowlist
- `src/security/audit-extra.ts:519-613` - warns but doesn't prevent

## Risk

- Allowlist is security theater
- Users think they're protected when they're not
- Unauthorized plugins can still load

## Detection

```bash
# Set allowlist
moltbot config set plugins.allow '["trusted-plugin"]'

# Install non-allowed plugin
moltbot plugin install other-plugin

# Check if it loaded anyway
moltbot plugin list
```

## Remediation

Enforce allowlist at load time:

```typescript
async function loadPlugin(pluginId: string) {
  const allowlist = config.get("plugins.allow");

  if (allowlist && allowlist.length > 0) {
    if (!allowlist.includes(pluginId)) {
      throw new Error(`Plugin ${pluginId} not in allowlist`);
    }
  }

  // Proceed with loading
}
```

Add `plugins.deny` for explicit blocking:

```typescript
const denylist = config.get("plugins.deny") || [];
if (denylist.includes(pluginId)) {
  throw new Error(`Plugin ${pluginId} is blocked`);
}
```

## References

- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
