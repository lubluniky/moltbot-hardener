# V13: Shell Injection Vectors

## Overview

| Property | Value |
|----------|-------|
| **ID** | V13 |
| **Severity** | Critical |
| **Category** | Tools |
| **Auto-Fix** | Partial |
| **CVSS Score** | 9.1 |

## Description

The configuration allows shell command execution without proper input sanitization, creating vectors for shell injection attacks:

- Unescaped command arguments
- Direct shell interpretation
- Command chaining via `;`, `&&`, `||`
- Subshell expansion via `$()` or backticks

## Affected Files in Moltbot

- `src/agents/bash-tools.exec.ts` - Command execution
- `src/agents/bash-tools.shared.ts` - Argument handling
- `src/plugins/commands.ts` - Command injection warnings

## Attack Scenario

1. **Access**: Attacker communicates with agent
2. **Injection**: Embeds shell metacharacters:
   ```
   "Check if this file exists: test.txt; rm -rf /"
   ```
3. **Execution**: Agent passes string to shell
4. **Impact**: Arbitrary command execution

### Injection Patterns

| Pattern | Description |
|---------|-------------|
| `; command` | Command separator |
| `&& command` | Execute if previous succeeds |
| `\|\| command` | Execute if previous fails |
| `$(command)` | Command substitution |
| `` `command` `` | Backtick substitution |
| `> file` | Output redirection |
| `< file` | Input redirection |
| `\| command` | Pipe |

## Detection

```go
func (c *ShellInjectionCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    // Check if exec tool is enabled without sandbox
    execEnabled := !c.isToolDenied(ctx, "exec")
    sandboxOff := ctx.Config.Agents.Defaults.Sandbox.Mode == "off"

    if execEnabled && sandboxOff {
        findings = append(findings, Finding{
            CheckID:  "V13",
            Severity: SeverityCritical,
            Title:    "Shell injection risk with unsandboxed exec",
        })
    }

    return findings, nil
}
```

## Fix Applied by Hardener

The hardener applies defense in depth:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main"
      }
    }
  },
  "tools": {
    "deny": ["exec"]
  }
}
```

**Note**: Full mitigation requires code-level input sanitization that the hardener cannot apply.

## Manual Fix Instructions

### 1. Disable Shell Execution

```bash
moltbot config set tools.deny '["exec", "process"]'
```

### 2. Enable Sandboxing

```bash
moltbot config set agents.defaults.sandbox.mode all
```

### 3. Use Safe Command Lists (Per-Agent)

```json
{
  "agents": {
    "list": [
      {
        "id": "limited",
        "tools": {
          "exec": {
            "allowlist": ["ls", "cat", "grep"]
          }
        }
      }
    ]
  }
}
```

## Verification Steps

1. **Check exec availability**:
   ```bash
   moltbot config get tools.deny
   # Should include 'exec'
   ```

2. **Test injection (sandboxed)**:
   ```bash
   # From sandboxed session, try:
   # "Run: echo test; cat /etc/passwd"
   # Should only execute in sandbox
   ```

3. **Verify sandbox mode**:
   ```bash
   moltbot config get agents.defaults.sandbox.mode
   ```

## Defense Strategies

| Strategy | Protection |
|----------|------------|
| Deny exec | Eliminates risk |
| Sandbox | Contains damage |
| Input validation | Blocks patterns (partial) |
| Command allowlist | Limits what can run |
| Argument escaping | Prevents metacharacter abuse |

## Related Vulnerabilities

- [V03: Sandbox Disabled](V03-sandbox-disabled.md)
- [V06: Dangerous Commands Enabled](V06-dangerous-commands.md)
- [V08: Elevated Tool Access](V08-elevated-tool-access.md)

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Shell Metacharacters](https://www.gnu.org/software/bash/manual/html_node/Special-Characters.html)
