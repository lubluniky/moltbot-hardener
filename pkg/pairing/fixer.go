// Package pairing provides security fixers for Moltbot pairing/onboarding configuration.
package pairing

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// DmScope represents the DM scope policy.
type DmScope string

const (
	DmScopeNone      DmScope = "none"      // No DM access
	DmScopeAllowlist DmScope = "allowlist" // Only allowlisted users
	DmScopeAnyone    DmScope = "anyone"    // Anyone can DM (dangerous)
)

// PairingPolicy represents a pairing security policy.
type PairingPolicy struct {
	RateLimitPerMinute int
	RateLimitPerHour   int
	RequireApproval    bool
	MaxPendingRequests int
	ExpirationMinutes  int
}

// Fixer provides methods to fix pairing security issues.
type Fixer struct {
	DryRun bool
	Logger *log.Logger
}

// NewFixer creates a new pairing fixer.
func NewFixer(dryRun bool) *Fixer {
	return &Fixer{
		DryRun: dryRun,
		Logger: log.New(os.Stdout, "[pairing-fixer] ", log.LstdFlags),
	}
}

// SetStrongPairingPolicy configures rate limits and security settings for pairing.
func (f *Fixer) SetStrongPairingPolicy(policy *PairingPolicy) error {
	f.Logger.Println("Setting strong pairing policy")

	// Use secure defaults if no policy provided
	if policy == nil {
		policy = &PairingPolicy{
			RateLimitPerMinute: 3,   // Max 3 pairing attempts per minute
			RateLimitPerHour:   10,  // Max 10 pairing attempts per hour
			RequireApproval:    true, // Require manual approval
			MaxPendingRequests: 5,   // Max 5 pending requests
			ExpirationMinutes:  15,  // Requests expire after 15 minutes
		}
	}

	configs := []struct {
		key   string
		value string
	}{
		{"pairing.rateLimitPerMinute", fmt.Sprintf("%d", policy.RateLimitPerMinute)},
		{"pairing.rateLimitPerHour", fmt.Sprintf("%d", policy.RateLimitPerHour)},
		{"pairing.requireApproval", fmt.Sprintf("%t", policy.RequireApproval)},
		{"pairing.maxPendingRequests", fmt.Sprintf("%d", policy.MaxPendingRequests)},
		{"pairing.expirationMinutes", fmt.Sprintf("%d", policy.ExpirationMinutes)},
	}

	for _, cfg := range configs {
		if f.DryRun {
			f.Logger.Printf("[DRY-RUN] Would set %s = %s", cfg.key, cfg.value)
			continue
		}

		cmd := exec.Command("moltbot", "config", "set", cfg.key, cfg.value)
		output, err := cmd.CombinedOutput()
		if err != nil {
			f.Logger.Printf("Warning: Failed to set %s: %v (output: %s)", cfg.key, err, string(output))
		} else {
			f.Logger.Printf("Set %s = %s", cfg.key, cfg.value)
		}
	}

	f.Logger.Println("Strong pairing policy configured")
	return nil
}

// ValidateDmScope checks the current DM scope setting and returns its value.
func (f *Fixer) ValidateDmScope(channel string) (DmScope, error) {
	f.Logger.Printf("Validating DM scope for channel: %s", channel)

	configKey := fmt.Sprintf("%s.dmScope", channel)
	cmd := exec.Command("moltbot", "config", "get", configKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		f.Logger.Printf("Could not read %s (may be unset): %v", configKey, err)
		return DmScopeNone, nil
	}

	scope := strings.TrimSpace(string(output))
	switch strings.ToLower(scope) {
	case "none", "disabled", "":
		f.Logger.Printf("DM scope for %s is secure (none/disabled)", channel)
		return DmScopeNone, nil
	case "allowlist", "whitelist":
		f.Logger.Printf("DM scope for %s is secure (allowlist)", channel)
		return DmScopeAllowlist, nil
	case "anyone", "all", "open":
		f.Logger.Printf("WARNING: DM scope for %s is insecure (anyone can message)", channel)
		return DmScopeAnyone, nil
	default:
		f.Logger.Printf("Unknown DM scope value: %s", scope)
		return DmScopeNone, nil
	}
}

// FixDmPolicy sets the DM policy to allowlist mode for a channel.
func (f *Fixer) FixDmPolicy(channel string) error {
	f.Logger.Printf("Setting DM policy to allowlist for channel: %s", channel)

	configKey := fmt.Sprintf("%s.dmScope", channel)

	if f.DryRun {
		f.Logger.Printf("[DRY-RUN] Would set %s = allowlist", configKey)
		return nil
	}

	cmd := exec.Command("moltbot", "config", "set", configKey, "allowlist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set %s: %w (output: %s)", configKey, err, string(output))
	}

	f.Logger.Printf("Successfully set %s to allowlist", configKey)
	return nil
}

// FixTelegramDmPolicy specifically fixes Telegram DM policy to allowlist.
func (f *Fixer) FixTelegramDmPolicy() error {
	return f.FixDmPolicy("telegram")
}

// GetAllChannelDmScopes returns the DM scope for all known channels.
func (f *Fixer) GetAllChannelDmScopes() map[string]DmScope {
	f.Logger.Println("Getting DM scopes for all channels")

	channels := []string{
		"telegram",
		"discord",
		"slack",
		"signal",
		"whatsapp",
		"imessage",
		"matrix",
		"msteams",
	}

	scopes := make(map[string]DmScope)
	for _, channel := range channels {
		scope, err := f.ValidateDmScope(channel)
		if err != nil {
			f.Logger.Printf("Could not get scope for %s: %v", channel, err)
			scopes[channel] = DmScopeNone
		} else {
			scopes[channel] = scope
		}
	}

	return scopes
}

// ValidateAllowlist checks if the allowlist for a channel is properly configured.
func (f *Fixer) ValidateAllowlist(channel string) (bool, []string, error) {
	f.Logger.Printf("Validating allowlist for channel: %s", channel)

	configKey := fmt.Sprintf("%s.allowlist", channel)
	cmd := exec.Command("moltbot", "config", "get", configKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		f.Logger.Printf("No allowlist configured for %s", channel)
		return false, nil, nil
	}

	allowlistStr := strings.TrimSpace(string(output))
	if allowlistStr == "" || allowlistStr == "[]" {
		f.Logger.Printf("Allowlist for %s is empty", channel)
		return false, nil, nil
	}

	// Parse the allowlist (simple string split for now)
	allowlistStr = strings.Trim(allowlistStr, "[]")
	entries := strings.Split(allowlistStr, ",")
	var allowlist []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		entry = strings.Trim(entry, "\"'")
		if entry != "" {
			allowlist = append(allowlist, entry)
		}
	}

	if len(allowlist) == 0 {
		f.Logger.Printf("Allowlist for %s has no valid entries", channel)
		return false, nil, nil
	}

	f.Logger.Printf("Allowlist for %s has %d entries", channel, len(allowlist))
	return true, allowlist, nil
}

// DisablePairing completely disables pairing for new users.
func (f *Fixer) DisablePairing() error {
	f.Logger.Println("Disabling pairing for new users")

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would set pairing.enabled = false")
		return nil
	}

	cmd := exec.Command("moltbot", "config", "set", "pairing.enabled", "false")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable pairing: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("Pairing disabled for new users")
	return nil
}

// EnablePairingWithApproval enables pairing but requires manual approval.
func (f *Fixer) EnablePairingWithApproval() error {
	f.Logger.Println("Enabling pairing with manual approval required")

	configs := []struct {
		key   string
		value string
	}{
		{"pairing.enabled", "true"},
		{"pairing.requireApproval", "true"},
	}

	for _, cfg := range configs {
		if f.DryRun {
			f.Logger.Printf("[DRY-RUN] Would set %s = %s", cfg.key, cfg.value)
			continue
		}

		cmd := exec.Command("moltbot", "config", "set", cfg.key, cfg.value)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set %s: %w (output: %s)", cfg.key, err, string(output))
		}
		f.Logger.Printf("Set %s = %s", cfg.key, cfg.value)
	}

	f.Logger.Println("Pairing enabled with approval requirement")
	return nil
}

// SetPairingCode sets a required pairing code for new connections.
func (f *Fixer) SetPairingCode(code string) error {
	f.Logger.Println("Setting pairing code requirement")

	if code == "" {
		return fmt.Errorf("pairing code cannot be empty")
	}

	if len(code) < 6 {
		f.Logger.Println("WARNING: Pairing code is short (< 6 characters)")
	}

	if f.DryRun {
		f.Logger.Printf("[DRY-RUN] Would set pairing.code = %s", code)
		return nil
	}

	cmd := exec.Command("moltbot", "config", "set", "pairing.code", code)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set pairing code: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("Pairing code configured")
	return nil
}

// AuditPairingStatus provides a comprehensive audit of pairing security settings.
func (f *Fixer) AuditPairingStatus() (map[string]interface{}, error) {
	f.Logger.Println("Auditing pairing security status")

	audit := make(map[string]interface{})

	// Check pairing enabled status
	cmd := exec.Command("moltbot", "config", "get", "pairing.enabled")
	output, _ := cmd.CombinedOutput()
	audit["pairing.enabled"] = strings.TrimSpace(string(output))

	// Check approval requirement
	cmd = exec.Command("moltbot", "config", "get", "pairing.requireApproval")
	output, _ = cmd.CombinedOutput()
	audit["pairing.requireApproval"] = strings.TrimSpace(string(output))

	// Check rate limits
	cmd = exec.Command("moltbot", "config", "get", "pairing.rateLimitPerMinute")
	output, _ = cmd.CombinedOutput()
	audit["pairing.rateLimitPerMinute"] = strings.TrimSpace(string(output))

	// Check DM scopes for all channels
	scopes := f.GetAllChannelDmScopes()
	insecureChannels := []string{}
	for channel, scope := range scopes {
		audit[fmt.Sprintf("%s.dmScope", channel)] = string(scope)
		if scope == DmScopeAnyone {
			insecureChannels = append(insecureChannels, channel)
		}
	}

	if len(insecureChannels) > 0 {
		audit["insecureChannels"] = insecureChannels
		f.Logger.Printf("WARNING: Insecure DM scope on channels: %v", insecureChannels)
	}

	// Print audit summary
	f.Logger.Println("\n--- Pairing Security Audit ---")
	for key, value := range audit {
		f.Logger.Printf("%s: %v", key, value)
	}

	return audit, nil
}

// FixAll applies all pairing security fixes.
func (f *Fixer) FixAll() error {
	f.Logger.Println("Applying all pairing security fixes")

	// Set strong pairing policy
	if err := f.SetStrongPairingPolicy(nil); err != nil {
		return fmt.Errorf("SetStrongPairingPolicy failed: %w", err)
	}

	// Enable pairing with approval
	if err := f.EnablePairingWithApproval(); err != nil {
		f.Logger.Printf("Warning: EnablePairingWithApproval failed: %v", err)
	}

	// Fix Telegram DM policy (most commonly misconfigured)
	if err := f.FixTelegramDmPolicy(); err != nil {
		f.Logger.Printf("Warning: FixTelegramDmPolicy failed: %v", err)
	}

	// Check all channel DM scopes
	scopes := f.GetAllChannelDmScopes()
	for channel, scope := range scopes {
		if scope == DmScopeAnyone {
			f.Logger.Printf("Fixing insecure DM scope for %s", channel)
			if err := f.FixDmPolicy(channel); err != nil {
				f.Logger.Printf("Warning: Could not fix DM policy for %s: %v", channel, err)
			}
		}
	}

	// Run audit
	f.AuditPairingStatus()

	f.Logger.Println("All pairing security fixes applied")
	return nil
}
