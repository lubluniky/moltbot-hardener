# V22: Legacy Model Risk

## Overview

| Property | Value |
|----------|-------|
| **ID** | V22 |
| **Severity** | High |
| **Category** | Models |
| **Auto-Fix** | Partial |
| **CVSS Score** | 6.8 |

## Description

The configuration uses legacy or weak-tier models that are more susceptible to:

- Prompt injection attacks
- Instruction hijacking
- Tool misuse
- Safety bypass attempts

## Legacy/Weak Models

| Model Pattern | Risk |
|---------------|------|
| `gpt-3.5*` | Legacy, less robust |
| `claude-2*`, `claude-instant*` | Legacy |
| `gpt-4-0314`, `gpt-4-0613` | Outdated snapshots |
| `*haiku*` | Smaller, weaker safety |
| Small models (<300B params) | Higher manipulation risk |

## Affected Files in Moltbot

- `src/security/audit-extra.ts` - Model hygiene checks
- `src/agents/models-config.ts` - Model configuration

## Detection

```go
func (c *ModelRiskCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    legacyPatterns := []string{
        "gpt-3.5", "claude-2", "claude-instant",
        "gpt-4-0314", "gpt-4-0613",
    }

    for _, model := range c.collectModels(ctx.Config) {
        for _, pattern := range legacyPatterns {
            if strings.Contains(model.ID, pattern) {
                findings = append(findings, Finding{
                    CheckID:  "V22",
                    Severity: SeverityHigh,
                    Title:    "Legacy model configured",
                    Detail:   fmt.Sprintf("%s at %s", model.ID, model.Source),
                })
            }
        }
    }

    return findings, nil
}
```

## Fix Applied by Hardener

The hardener cannot automatically change models (may break workflows), but warns and suggests:

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "claude-opus-4-5-20251101"
      }
    }
  }
}
```

## Manual Fix Instructions

### Update Primary Model

```bash
# Use Claude Opus 4.5 (recommended)
moltbot config set agents.defaults.model.primary "claude-opus-4-5-20251101"

# Or GPT-5+
moltbot config set agents.defaults.model.primary "gpt-5"
```

### Update Per-Agent Models

```json
{
  "agents": {
    "list": [
      {
        "id": "personal",
        "model": {
          "primary": "claude-opus-4-5-20251101",
          "fallbacks": ["gpt-5"]
        }
      }
    ]
  }
}
```

## Verification Steps

```bash
moltbot config get agents.defaults.model.primary
# Should be modern model

moltbot security audit
# Should not warn about legacy models
```

## Model Recommendations

| Use Case | Recommended |
|----------|-------------|
| Tools enabled | Claude Opus 4.5, GPT-5+ |
| Untrusted input | Claude Opus 4.5, GPT-5+ |
| Chat only (trusted) | Any modern model |
| Development/testing | Lower tier OK |

## Related Vulnerabilities

- [V05: Prompt Injection Surface](V05-prompt-injection.md)
- [V06: Dangerous Commands Enabled](V06-dangerous-commands.md)

## References

- [Moltbot Model Security](https://docs.molt.bot/gateway/security#model-strength)
- [Anthropic Claude Safety](https://www.anthropic.com/news/claude-opus-4-5)
