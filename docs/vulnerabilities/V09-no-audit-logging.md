# V09: No Audit Logging

## Overview

| Property | Value |
|----------|-------|
| **ID** | V09 |
| **Severity** | Medium |
| **Category** | Logging |
| **Auto-Fix** | Yes |
| **CVSS Score** | 5.3 |

## Description

Audit logging is disabled or not configured, making it difficult to:

- Detect security incidents
- Investigate unauthorized access
- Track tool usage and commands
- Maintain compliance records
- Perform forensic analysis after compromise

## Affected Files in Moltbot

- `src/logging/config.ts` - Logging configuration
- `src/security/audit.ts` - Audit event generation
- `src/telegram/audit.ts` - Channel-specific audit
- `src/discord/audit.ts` - Channel-specific audit

## Attack Scenario

1. **Compromise**: Attacker gains access to agent
2. **Operation**: Executes commands, accesses data
3. **Cover Tracks**: Without logging, no evidence remains
4. **Discovery Delay**: Attack may go unnoticed indefinitely

## Detection

```go
func (c *AuditLoggingCheck) Run(ctx *CheckContext) ([]Finding, error) {
    logFile := ctx.Config.Logging.File
    if logFile == "" {
        return []Finding{{
            CheckID:  "V09",
            Severity: SeverityMedium,
            Title:    "No audit log file configured",
            Detail:   "logging.file is not set",
        }}, nil
    }

    return nil, nil
}
```

## Fix Applied by Hardener

```json
{
  "logging": {
    "file": "~/.moltbot/logs/moltbot.log",
    "redactSensitive": "tools"
  }
}
```

## Manual Fix Instructions

### Enable File Logging

```bash
# Set log file path
moltbot config set logging.file "~/.moltbot/logs/moltbot.log"

# Ensure directory exists
mkdir -p ~/.moltbot/logs
chmod 700 ~/.moltbot/logs
```

### Configure Log Rotation

Use system tools for log rotation:

```bash
# /etc/logrotate.d/moltbot
~/.moltbot/logs/moltbot.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 600 user user
}
```

### Enable Sensitive Data Redaction

```bash
moltbot config set logging.redactSensitive tools
```

## Verification Steps

1. **Check logging config**:
   ```bash
   moltbot config get logging.file
   # Should return a valid path
   ```

2. **Verify log creation**:
   ```bash
   ls -la ~/.moltbot/logs/
   # Should show log files
   ```

3. **Check log permissions**:
   ```bash
   ls -la ~/.moltbot/logs/moltbot.log
   # Should be 600 (owner only)
   ```

4. **Test log writing**:
   ```bash
   # Send a message and check log
   tail -f ~/.moltbot/logs/moltbot.log
   ```

## What Gets Logged

| Event | Information |
|-------|-------------|
| Message received | Channel, sender, timestamp |
| Tool invoked | Tool name, (redacted) arguments |
| Session created | Session key, agent ID |
| Config changed | Key, old value, new value |
| Error occurred | Error type, stack trace |

## Related Vulnerabilities

- [V04: Plaintext Credentials](V04-plaintext-credentials.md) - Log file permissions
- [V18: State Directory Exposure](V18-state-dir-exposure.md) - Log file location

## References

- [Moltbot Logging Documentation](https://docs.molt.bot/gateway/logging)
- [Incident Response Guide](https://docs.molt.bot/gateway/security#incident-response)
