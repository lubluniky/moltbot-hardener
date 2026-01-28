// Package sandbox provides security fixers for Moltbot sandbox configuration.
package sandbox

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// DangerousMount represents a potentially dangerous bind mount.
type DangerousMount struct {
	Path   string
	Reason string
	Risk   string // "critical", "high", "medium", "low"
}

// Fixer provides methods to fix sandbox security issues.
type Fixer struct {
	DryRun      bool
	Interactive bool                       // Prompt user for confirmation on risky fixes
	ConfirmFunc func(msg string) bool      // Custom confirmation function
	Logger      *log.Logger
}

// NewFixer creates a new sandbox fixer.
func NewFixer(dryRun bool) *Fixer {
	return &Fixer{
		DryRun:      dryRun,
		Interactive: false,
		Logger:      log.New(os.Stdout, "[sandbox-fixer] ", log.LstdFlags),
	}
}

// NewInteractiveFixer creates a fixer that prompts for confirmation on risky operations.
func NewInteractiveFixer(confirmFunc func(msg string) bool) *Fixer {
	return &Fixer{
		DryRun:      false,
		Interactive: true,
		ConfirmFunc: confirmFunc,
		Logger:      log.New(os.Stdout, "[sandbox-fixer] ", log.LstdFlags),
	}
}

// confirm asks user for confirmation if in interactive mode.
func (f *Fixer) confirm(msg string) bool {
	if !f.Interactive || f.ConfirmFunc == nil {
		return true // Auto-approve if not interactive
	}
	return f.ConfirmFunc(msg)
}

// EnableSandbox sets the sandbox mode to "all", enabling sandboxing for all code execution.
// This is a PARTIAL fix - may break existing workflows with custom bind mounts or setup commands.
func (f *Fixer) EnableSandbox() error {
	f.Logger.Println("Enabling sandbox mode for all code execution")
	f.Logger.Println("⚠️  WARNING: This may break existing workflows with custom bind mounts or setup commands")

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would execute: moltbot config set sandbox.mode all")
		return nil
	}

	// Check for existing bind mounts that might break
	if f.Interactive {
		mounts, _ := f.ValidateBindMounts()
		if len(mounts) > 0 {
			f.Logger.Printf("Found %d bind mounts that may be affected", len(mounts))
		}

		if !f.confirm("Enable sandbox mode? This may break existing workflows.") {
			f.Logger.Println("Skipped: User declined sandbox enablement")
			return nil
		}
	}

	cmd := exec.Command("moltbot", "config", "set", "sandbox.mode", "all")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable sandbox: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("✅ Successfully enabled sandbox mode")
	return nil
}

// SetNetworkNone sets docker.network to "none", disabling network access for sandboxed containers.
func (f *Fixer) SetNetworkNone() error {
	f.Logger.Println("Setting docker network to 'none' (no network access)")

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would execute: moltbot config set sandbox.docker.network none")
		return nil
	}

	cmd := exec.Command("moltbot", "config", "set", "sandbox.docker.network", "none")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set network to none: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("Successfully set docker network to none")
	return nil
}

// DropAllCaps sets capDrop to ["ALL"], removing all Linux capabilities from containers.
func (f *Fixer) DropAllCaps() error {
	f.Logger.Println("Dropping all Linux capabilities from sandbox containers")

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would execute: moltbot config set sandbox.docker.capDrop [\"ALL\"]")
		return nil
	}

	// Set capDrop to ALL
	cmd := exec.Command("moltbot", "config", "set", "sandbox.docker.capDrop", "[\"ALL\"]")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to drop all capabilities: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("Successfully dropped all Linux capabilities")
	return nil
}

// ValidateBindMounts checks for dangerous bind mounts and returns a list of issues.
func (f *Fixer) ValidateBindMounts() ([]DangerousMount, error) {
	f.Logger.Println("Validating bind mounts for security risks")

	// Get current bind mounts configuration
	cmd := exec.Command("moltbot", "config", "get", "sandbox.docker.bindMounts")
	output, err := cmd.CombinedOutput()
	if err != nil {
		f.Logger.Println("No bind mounts configured (this is good)")
		return nil, nil
	}

	mounts := strings.TrimSpace(string(output))
	if mounts == "" || mounts == "[]" {
		f.Logger.Println("No bind mounts configured (this is good)")
		return nil, nil
	}

	// Check for dangerous mount patterns
	dangerousPaths := map[string]struct {
		reason string
		risk   string
	}{
		"/":                {"Root filesystem access allows complete host compromise", "critical"},
		"/etc":             {"Access to system configuration files", "critical"},
		"/etc/passwd":      {"Access to user database", "high"},
		"/etc/shadow":      {"Access to password hashes", "critical"},
		"/root":            {"Access to root user home directory", "critical"},
		"/home":            {"Access to all user home directories", "high"},
		"/var/run/docker":  {"Docker socket access allows container escape", "critical"},
		"/var/run/docker.sock": {"Docker socket access allows container escape", "critical"},
		"/proc":            {"Process information leak and potential exploitation", "high"},
		"/sys":             {"System configuration access", "high"},
		"/dev":             {"Device access can lead to privilege escalation", "critical"},
		"~/.ssh":           {"SSH key theft", "critical"},
		"~/.aws":           {"AWS credential theft", "critical"},
		"~/.config":        {"Application configuration and secrets theft", "high"},
		"~/.clawdbot":      {"Moltbot credentials and session data", "critical"},
	}

	var dangerous []DangerousMount

	for path, info := range dangerousPaths {
		if strings.Contains(mounts, path) {
			dangerous = append(dangerous, DangerousMount{
				Path:   path,
				Reason: info.reason,
				Risk:   info.risk,
			})
			f.Logger.Printf("DANGEROUS: Found mount of '%s' - %s (risk: %s)", path, info.reason, info.risk)
		}
	}

	if len(dangerous) == 0 {
		f.Logger.Println("No dangerous bind mounts detected")
	} else {
		f.Logger.Printf("Found %d dangerous bind mount(s)", len(dangerous))
	}

	return dangerous, nil
}

// RestrictSetupCommand checks and warns about dangerous setup commands.
func (f *Fixer) RestrictSetupCommand() ([]string, error) {
	f.Logger.Println("Checking sandbox setup command for security risks")

	cmd := exec.Command("moltbot", "config", "get", "sandbox.docker.setupCommand")
	output, err := cmd.CombinedOutput()
	if err != nil {
		f.Logger.Println("No setup command configured")
		return nil, nil
	}

	setupCmd := strings.TrimSpace(string(output))
	if setupCmd == "" {
		f.Logger.Println("No setup command configured")
		return nil, nil
	}

	var warnings []string

	// Check for dangerous patterns
	dangerousPatterns := map[string]string{
		"curl":            "curl can download and execute arbitrary code",
		"wget":            "wget can download and execute arbitrary code",
		"chmod +x":        "Making files executable could allow code execution",
		"sudo":            "sudo usage in container could indicate privilege escalation",
		"apt install":     "Package installation could add vulnerable or malicious packages",
		"pip install":     "pip install without version pinning is dangerous",
		"npm install -g":  "Global npm installs could be compromised",
		"eval":            "eval can execute arbitrary code",
		"bash -c":         "bash -c can execute arbitrary code",
		"sh -c":           "sh -c can execute arbitrary code",
		"$(":              "Command substitution could execute untrusted code",
		"`":               "Backtick command substitution is dangerous",
	}

	for pattern, reason := range dangerousPatterns {
		if strings.Contains(strings.ToLower(setupCmd), strings.ToLower(pattern)) {
			warning := fmt.Sprintf("Setup command contains '%s': %s", pattern, reason)
			warnings = append(warnings, warning)
			f.Logger.Printf("WARNING: %s", warning)
		}
	}

	if len(warnings) == 0 {
		f.Logger.Println("No obvious security issues in setup command")
	}

	return warnings, nil
}

// DisableHostControl sets allowHostControl to false, preventing container escape vectors.
func (f *Fixer) DisableHostControl() error {
	f.Logger.Println("Disabling host control from sandbox containers")

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would execute: moltbot config set sandbox.allowHostControl false")
		return nil
	}

	cmd := exec.Command("moltbot", "config", "set", "sandbox.allowHostControl", "false")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable host control: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("Successfully disabled host control")
	return nil
}

// GetSandboxStatus returns the current sandbox configuration status.
func (f *Fixer) GetSandboxStatus() (map[string]string, error) {
	f.Logger.Println("Getting sandbox configuration status")

	status := make(map[string]string)

	configs := []string{
		"sandbox.mode",
		"sandbox.docker.network",
		"sandbox.docker.capDrop",
		"sandbox.allowHostControl",
	}

	for _, config := range configs {
		cmd := exec.Command("moltbot", "config", "get", config)
		output, err := cmd.CombinedOutput()
		if err != nil {
			status[config] = "(not set)"
		} else {
			status[config] = strings.TrimSpace(string(output))
		}
	}

	return status, nil
}

// FixAll applies all sandbox security fixes.
func (f *Fixer) FixAll() error {
	f.Logger.Println("Applying all sandbox security fixes")

	// Enable sandbox for all code
	if err := f.EnableSandbox(); err != nil {
		return fmt.Errorf("EnableSandbox failed: %w", err)
	}

	// Disable network access
	if err := f.SetNetworkNone(); err != nil {
		return fmt.Errorf("SetNetworkNone failed: %w", err)
	}

	// Drop all capabilities
	if err := f.DropAllCaps(); err != nil {
		return fmt.Errorf("DropAllCaps failed: %w", err)
	}

	// Disable host control
	if err := f.DisableHostControl(); err != nil {
		return fmt.Errorf("DisableHostControl failed: %w", err)
	}

	// Validate bind mounts (this doesn't fix, just reports)
	mounts, err := f.ValidateBindMounts()
	if err != nil {
		f.Logger.Printf("Warning: Could not validate bind mounts: %v", err)
	}
	if len(mounts) > 0 {
		f.Logger.Printf("WARNING: %d dangerous bind mount(s) detected - manual review required", len(mounts))
	}

	// Check setup command
	warnings, err := f.RestrictSetupCommand()
	if err != nil {
		f.Logger.Printf("Warning: Could not check setup command: %v", err)
	}
	if len(warnings) > 0 {
		f.Logger.Printf("WARNING: %d issue(s) found in setup command - manual review required", len(warnings))
	}

	f.Logger.Println("All sandbox security fixes applied successfully")
	return nil
}
