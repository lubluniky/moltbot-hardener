// Package credentials provides security fixers for Moltbot credential management.
package credentials

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// PermissionIssue represents a file permission security issue.
type PermissionIssue struct {
	Path        string
	Current     fs.FileMode
	Recommended fs.FileMode
	Reason      string
}

// SyncedFolderRisk represents a cloud sync folder risk.
type SyncedFolderRisk struct {
	Path        string
	SyncService string
	Risk        string
	Reason      string
}

// EnvVarMigration represents a credential that should be migrated to env vars.
type EnvVarMigration struct {
	SourceFile string
	Key        string
	EnvVarName string
	Migrated   bool
}

// Fixer provides methods to fix credential security issues.
type Fixer struct {
	DryRun bool
	Logger *log.Logger
}

// NewFixer creates a new credentials fixer.
func NewFixer(dryRun bool) *Fixer {
	return &Fixer{
		DryRun: dryRun,
		Logger: log.New(os.Stdout, "[credentials-fixer] ", log.LstdFlags),
	}
}

// FixPermissions ensures credential files have secure permissions (600 for files, 700 for directories).
func (f *Fixer) FixPermissions(credentialsDir string) ([]PermissionIssue, error) {
	f.Logger.Printf("Checking permissions in %s", credentialsDir)

	if credentialsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		credentialsDir = filepath.Join(home, ".clawdbot", "credentials")
	}

	var issues []PermissionIssue

	err := filepath.WalkDir(credentialsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				f.Logger.Printf("Credentials directory does not exist: %s", credentialsDir)
				return nil
			}
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode().Perm()
		var recommended fs.FileMode
		var reason string

		if d.IsDir() {
			recommended = 0700
			reason = "Directories containing credentials should only be accessible by owner"
		} else {
			recommended = 0600
			reason = "Credential files should only be readable/writable by owner"
		}

		// Check if permissions are too permissive
		if mode&0077 != 0 { // Group or other has any permissions
			issue := PermissionIssue{
				Path:        path,
				Current:     mode,
				Recommended: recommended,
				Reason:      reason,
			}
			issues = append(issues, issue)
			f.Logger.Printf("INSECURE: %s has mode %o (should be %o)", path, mode, recommended)

			if !f.DryRun {
				if err := os.Chmod(path, recommended); err != nil {
					f.Logger.Printf("Failed to fix permissions on %s: %v", path, err)
				} else {
					f.Logger.Printf("Fixed permissions on %s: %o -> %o", path, mode, recommended)
				}
			} else {
				f.Logger.Printf("[DRY-RUN] Would chmod %o %s", recommended, path)
			}
		}

		return nil
	})

	if err != nil {
		return issues, fmt.Errorf("failed to walk credentials directory: %w", err)
	}

	if len(issues) == 0 {
		f.Logger.Println("All credential file permissions are secure")
	} else {
		f.Logger.Printf("Found %d permission issue(s)", len(issues))
	}

	return issues, nil
}

// MigrateToEnvVars helps migrate plaintext credentials to environment variables.
func (f *Fixer) MigrateToEnvVars(credentialsDir string) ([]EnvVarMigration, error) {
	f.Logger.Println("Scanning for credentials that should be migrated to environment variables")

	if credentialsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		credentialsDir = filepath.Join(home, ".clawdbot", "credentials")
	}

	var migrations []EnvVarMigration

	// Known credential files and their recommended env var names
	credentialMappings := map[string]string{
		"anthropic.json":        "ANTHROPIC_API_KEY",
		"openai.json":           "OPENAI_API_KEY",
		"telegram.json":         "TELEGRAM_BOT_TOKEN",
		"discord.json":          "DISCORD_BOT_TOKEN",
		"slack.json":            "SLACK_BOT_TOKEN",
		"google.json":           "GOOGLE_API_KEY",
		"aws.json":              "AWS_ACCESS_KEY_ID",
		"github.json":           "GITHUB_TOKEN",
		"twilio.json":           "TWILIO_AUTH_TOKEN",
	}

	err := filepath.WalkDir(credentialsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if d.IsDir() {
			return nil
		}

		filename := d.Name()
		if envVar, ok := credentialMappings[filename]; ok {
			// Check if env var is already set
			_, envExists := os.LookupEnv(envVar)

			migration := EnvVarMigration{
				SourceFile: path,
				Key:        filename,
				EnvVarName: envVar,
				Migrated:   envExists,
			}
			migrations = append(migrations, migration)

			if envExists {
				f.Logger.Printf("OK: %s is already set as env var %s", filename, envVar)
			} else {
				f.Logger.Printf("RECOMMEND: Migrate %s to env var %s", path, envVar)
			}
		}

		return nil
	})

	if err != nil {
		return migrations, fmt.Errorf("failed to walk credentials directory: %w", err)
	}

	// Print migration instructions
	if len(migrations) > 0 {
		f.Logger.Println("\n--- Migration Instructions ---")
		f.Logger.Println("Add these to your shell profile (~/.bashrc, ~/.zshrc, etc.):")
		for _, m := range migrations {
			if !m.Migrated {
				f.Logger.Printf("export %s='<value from %s>'", m.EnvVarName, m.SourceFile)
			}
		}
		f.Logger.Println("\nThen run: moltbot config set credentials.useEnvVars true")
	}

	return migrations, nil
}

// CheckSyncedFolders detects if credential directories are in cloud-synced folders.
func (f *Fixer) CheckSyncedFolders(credentialsDir string) ([]SyncedFolderRisk, error) {
	f.Logger.Println("Checking for cloud-synced folder risks")

	if credentialsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		credentialsDir = filepath.Join(home, ".clawdbot")
	}

	var risks []SyncedFolderRisk

	// Resolve the real path (follow symlinks)
	realPath, err := filepath.EvalSymlinks(credentialsDir)
	if err != nil {
		if os.IsNotExist(err) {
			f.Logger.Printf("Credentials directory does not exist: %s", credentialsDir)
			return nil, nil
		}
		realPath = credentialsDir
	}

	home, _ := os.UserHomeDir()

	// Known cloud sync folder patterns
	syncFolders := []struct {
		pathPattern string
		service     string
		reason      string
	}{
		{filepath.Join(home, "Library/Mobile Documents"), "iCloud", "Files synced to iCloud can be accessed from other devices"},
		{filepath.Join(home, "iCloud Drive"), "iCloud", "Files synced to iCloud can be accessed from other devices"},
		{filepath.Join(home, "Dropbox"), "Dropbox", "Files synced to Dropbox servers and other devices"},
		{filepath.Join(home, "Google Drive"), "Google Drive", "Files synced to Google servers and other devices"},
		{filepath.Join(home, "OneDrive"), "OneDrive", "Files synced to Microsoft servers and other devices"},
		{filepath.Join(home, "Box"), "Box", "Files synced to Box servers"},
		{"/Users/Shared", "Shared", "Files accessible to all users on this Mac"},
	}

	for _, sync := range syncFolders {
		if strings.HasPrefix(realPath, sync.pathPattern) {
			risk := SyncedFolderRisk{
				Path:        credentialsDir,
				SyncService: sync.service,
				Risk:        "critical",
				Reason:      sync.reason,
			}
			risks = append(risks, risk)
			f.Logger.Printf("CRITICAL: Credentials directory is in %s folder: %s", sync.service, realPath)
		}
	}

	// Check for symlinks pointing to sync folders
	if realPath != credentialsDir {
		f.Logger.Printf("Note: %s is a symlink to %s", credentialsDir, realPath)
		for _, sync := range syncFolders {
			if strings.HasPrefix(realPath, sync.pathPattern) {
				risk := SyncedFolderRisk{
					Path:        credentialsDir,
					SyncService: sync.service + " (via symlink)",
					Risk:        "critical",
					Reason:      fmt.Sprintf("Symlink points to %s folder: %s", sync.service, sync.reason),
				}
				risks = append(risks, risk)
				f.Logger.Printf("CRITICAL: Credentials symlink points to %s: %s -> %s", sync.service, credentialsDir, realPath)
			}
		}
	}

	// Check if any parent is a symlink to a sync folder
	dir := credentialsDir
	for dir != "/" && dir != home {
		parent := filepath.Dir(dir)
		parentReal, err := filepath.EvalSymlinks(parent)
		if err == nil && parentReal != parent {
			for _, sync := range syncFolders {
				if strings.HasPrefix(parentReal, sync.pathPattern) {
					risk := SyncedFolderRisk{
						Path:        credentialsDir,
						SyncService: sync.service + " (parent symlink)",
						Risk:        "critical",
						Reason:      fmt.Sprintf("Parent %s symlinks to %s: %s", parent, sync.service, parentReal),
					}
					risks = append(risks, risk)
					f.Logger.Printf("CRITICAL: Parent directory symlinks to %s: %s -> %s", sync.service, parent, parentReal)
				}
			}
		}
		dir = parent
	}

	if len(risks) == 0 {
		f.Logger.Println("No cloud-synced folder risks detected")
	} else {
		f.Logger.Printf("Found %d synced folder risk(s)", len(risks))
		f.Logger.Println("\n--- Recommendations ---")
		f.Logger.Println("1. Move ~/.clawdbot to a non-synced location")
		f.Logger.Println("2. Or exclude ~/.clawdbot from sync in your cloud service settings")
		f.Logger.Println("3. Consider using environment variables instead of credential files")
	}

	return risks, nil
}

// ScanForPlaintextSecrets scans for obvious plaintext secrets in config files.
func (f *Fixer) ScanForPlaintextSecrets(configDir string) ([]string, error) {
	f.Logger.Println("Scanning for plaintext secrets in configuration files")

	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".clawdbot")
	}

	var findings []string

	// Patterns that indicate plaintext secrets
	secretPatterns := []string{
		"sk-",          // OpenAI API keys
		"sk-ant-",      // Anthropic API keys
		"ghp_",         // GitHub personal access tokens
		"gho_",         // GitHub OAuth tokens
		"github_pat_",  // GitHub PATs
		"xoxb-",        // Slack bot tokens
		"xoxp-",        // Slack user tokens
		"AKIA",         // AWS access key IDs
		"-----BEGIN",   // Private keys
		"-----BEGIN RSA",
		"-----BEGIN OPENSSH",
	}

	err := filepath.WalkDir(configDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		// Skip binary files and large files
		info, _ := d.Info()
		if info.Size() > 1024*1024 { // Skip files > 1MB
			return nil
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".toml" && ext != ".env" && ext != "" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		contentStr := string(content)
		for _, pattern := range secretPatterns {
			if strings.Contains(contentStr, pattern) {
				finding := fmt.Sprintf("Potential secret (%s...) found in: %s", pattern, path)
				findings = append(findings, finding)
				f.Logger.Printf("WARNING: %s", finding)
			}
		}

		return nil
	})

	if err != nil {
		return findings, fmt.Errorf("failed to scan for secrets: %w", err)
	}

	if len(findings) == 0 {
		f.Logger.Println("No obvious plaintext secrets found")
	} else {
		f.Logger.Printf("Found %d potential plaintext secret(s)", len(findings))
		f.Logger.Println("\nConsider migrating these to environment variables or a secrets manager")
	}

	return findings, nil
}

// FixAll applies all credential security fixes.
func (f *Fixer) FixAll() error {
	f.Logger.Println("Applying all credential security fixes")

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	clawdbotDir := filepath.Join(home, ".clawdbot")
	credentialsDir := filepath.Join(clawdbotDir, "credentials")

	// Fix permissions
	_, err = f.FixPermissions(credentialsDir)
	if err != nil {
		f.Logger.Printf("Warning: FixPermissions encountered error: %v", err)
	}

	// Check for synced folders
	risks, err := f.CheckSyncedFolders(clawdbotDir)
	if err != nil {
		f.Logger.Printf("Warning: CheckSyncedFolders encountered error: %v", err)
	}
	if len(risks) > 0 {
		f.Logger.Printf("WARNING: %d synced folder risk(s) require manual attention", len(risks))
	}

	// Scan for plaintext secrets
	secrets, err := f.ScanForPlaintextSecrets(clawdbotDir)
	if err != nil {
		f.Logger.Printf("Warning: ScanForPlaintextSecrets encountered error: %v", err)
	}
	if len(secrets) > 0 {
		f.Logger.Printf("WARNING: %d plaintext secret(s) found - consider migration", len(secrets))
	}

	// Provide migration guidance
	_, err = f.MigrateToEnvVars(credentialsDir)
	if err != nil {
		f.Logger.Printf("Warning: MigrateToEnvVars encountered error: %v", err)
	}

	f.Logger.Println("Credential security fixes completed")
	return nil
}
