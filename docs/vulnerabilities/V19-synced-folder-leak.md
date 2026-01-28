# V19: Synced Folder Leak

## Overview

| Property | Value |
|----------|-------|
| **ID** | V19 |
| **Severity** | High |
| **Category** | Filesystem |
| **Auto-Fix** | Partial |
| **CVSS Score** | 6.5 |

## Description

The moltbot state or config directory is located within a cloud-synced folder (iCloud, Dropbox, OneDrive, Google Drive), potentially exposing:

- Credentials to cloud provider
- Sync to other devices
- Unintended backup exposure

## Detection

```go
func (c *SyncedFolderCheck) Run(ctx *CheckContext) ([]Finding, error) {
    syncPatterns := []string{
        "icloud", "dropbox", "google drive",
        "googledrive", "onedrive",
    }

    pathLower := strings.ToLower(ctx.StateDir)
    for _, pattern := range syncPatterns {
        if strings.Contains(pathLower, pattern) {
            return []Finding{{
                CheckID:  "V19",
                Severity: SeverityHigh,
                Title:    "State directory in synced folder",
                Detail:   fmt.Sprintf("path contains '%s'", pattern),
            }}, nil
        }
    }

    return nil, nil
}
```

## Fix Applied by Hardener

The hardener warns but cannot automatically move files.

**Recommendation**: Set `CLAWDBOT_STATE_DIR` to a local-only path.

## Manual Fix Instructions

### Move State Directory

```bash
# Stop moltbot gateway
# Move state to local path
mv ~/.moltbot /usr/local/var/moltbot

# Set environment variable
export CLAWDBOT_STATE_DIR=/usr/local/var/moltbot

# Add to shell profile
echo 'export CLAWDBOT_STATE_DIR=/usr/local/var/moltbot' >> ~/.zshrc
```

### Exclude from Sync

If you can't move, exclude from sync:

- **iCloud**: Create `.nosync` file or folder
- **Dropbox**: Settings -> Selective Sync
- **OneDrive**: Settings -> Backup -> Manage folders
- **Google Drive**: Settings -> Preferences

## Verification Steps

```bash
echo $CLAWDBOT_STATE_DIR
# Should not be in synced folder

# Check actual path
ls -la ~/.moltbot
# Verify not symlinked to synced location
```

## Related Vulnerabilities

- [V04: Plaintext Credentials](V04-plaintext-credentials.md)
- [V18: State Directory Exposure](V18-state-dir-exposure.md)

## References

- [Moltbot Security - Synced Folders](https://docs.molt.bot/gateway/security#synced-folder-leak)
