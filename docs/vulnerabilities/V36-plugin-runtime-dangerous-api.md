# V36: Plugin Runtime Exposes Dangerous API

**Severity:** HIGH
**Category:** Plugins
**Auto-Fix:** No (requires code change)

## Description

The `PluginRuntime` object gives all plugins access to dangerous functions including `writeConfigFile`, `runCommandWithTimeout`, and channel send functions.

## Affected Code

- `src/plugins/runtime/index.ts:165-357`

## Exposed Capabilities

```typescript
runtime.config.writeConfigFile(path, content)  // Write any config
runtime.system.runCommandWithTimeout(cmd)       // Execute commands
runtime.telegram.sendMessage(...)               // Send as bot
runtime.discord.sendMessage(...)                // Send as bot
runtime.slack.sendMessage(...)                  // Send as bot
```

## Risk

- Any plugin can modify core configuration
- Command execution with bot privileges
- Impersonation via messaging channels
- No permission model

## Detection

```bash
# Check what plugins use dangerous APIs
grep -r "writeConfigFile\|runCommandWithTimeout" ~/.clawdbot/plugins/
```

## Remediation

1. Implement capability-based permissions:
```typescript
const PLUGIN_CAPABILITIES = {
  "trusted-plugin": ["config.read", "telegram.send"],
  "untrusted-plugin": ["config.read"]  // read-only
};

function getPluginRuntime(pluginId: string): PluginRuntime {
  const caps = PLUGIN_CAPABILITIES[pluginId] || [];
  return createScopedRuntime(caps);
}
```

2. Require explicit opt-in for dangerous capabilities:
```json
{
  "name": "my-plugin",
  "capabilities": ["config.write", "system.exec"]
}
```

3. Audit log all sensitive API calls

## References

- [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)
