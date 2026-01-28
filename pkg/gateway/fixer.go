// Package gateway provides security fixers for Moltbot gateway configuration.
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// BindMode represents the gateway bind mode.
type BindMode string

const (
	BindModeLoopback BindMode = "loopback"
	BindModeAll      BindMode = "all"
	BindModeUnknown  BindMode = "unknown"
)

// Fixer provides methods to fix gateway security issues.
type Fixer struct {
	DryRun bool
	Logger *log.Logger
}

// NewFixer creates a new gateway fixer.
func NewFixer(dryRun bool) *Fixer {
	return &Fixer{
		DryRun: dryRun,
		Logger: log.New(os.Stdout, "[gateway-fixer] ", log.LstdFlags),
	}
}

// ForceLoopback sets gateway.bind to loopback mode.
// This ensures the gateway only listens on localhost, preventing external access.
func (f *Fixer) ForceLoopback() error {
	f.Logger.Println("Setting gateway.bind to loopback mode")

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would execute: moltbot config set gateway.bind loopback")
		return nil
	}

	cmd := exec.Command("moltbot", "config", "set", "gateway.bind", "loopback")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set gateway.bind to loopback: %w (output: %s)", err, string(output))
	}

	f.Logger.Println("Successfully set gateway.bind to loopback")
	return nil
}

// SetAuthToken generates and sets a secure random authentication token.
// The token is 32 bytes (64 hex characters) of cryptographically secure randomness.
func (f *Fixer) SetAuthToken() (string, error) {
	f.Logger.Println("Generating secure authentication token")

	// Generate 32 bytes of random data
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)

	if f.DryRun {
		f.Logger.Printf("[DRY-RUN] Would set gateway.authToken to: %s...%s (truncated)", token[:8], token[len(token)-8:])
		return token, nil
	}

	cmd := exec.Command("moltbot", "config", "set", "gateway.authToken", token)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to set gateway.authToken: %w (output: %s)", err, string(output))
	}

	f.Logger.Printf("Successfully set gateway.authToken (token starts with: %s...)", token[:8])
	return token, nil
}

// ValidateBindMode checks the current gateway bind mode and returns it.
func (f *Fixer) ValidateBindMode() (BindMode, error) {
	f.Logger.Println("Validating gateway bind mode")

	cmd := exec.Command("moltbot", "config", "get", "gateway.bind")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If the key doesn't exist, it might default to something
		f.Logger.Printf("Could not read gateway.bind (may be unset): %v", err)
		return BindModeUnknown, nil
	}

	mode := strings.TrimSpace(string(output))
	switch mode {
	case "loopback", "127.0.0.1", "localhost":
		f.Logger.Println("Gateway bind mode is secure (loopback)")
		return BindModeLoopback, nil
	case "all", "0.0.0.0", "":
		f.Logger.Println("WARNING: Gateway bind mode allows external connections")
		return BindModeAll, nil
	default:
		f.Logger.Printf("Unknown bind mode: %s", mode)
		return BindModeUnknown, nil
	}
}

// FixStartupLogging provides recommendations for improving startup logging.
// Returns a list of recommended logging configuration changes.
func (f *Fixer) FixStartupLogging() []string {
	f.Logger.Println("Generating startup logging recommendations")

	recommendations := []string{
		"Set gateway.logLevel to 'info' for production (avoid 'debug' which may log sensitive data)",
		"Enable gateway.logFile to persist logs for security auditing",
		"Consider setting gateway.logRotate to prevent disk exhaustion",
		"Disable gateway.logRequests in production to avoid logging sensitive request bodies",
		"Enable gateway.logConnections to track client connections for security monitoring",
	}

	for i, rec := range recommendations {
		f.Logger.Printf("Recommendation %d: %s", i+1, rec)
	}

	return recommendations
}

// CheckAuthTokenSet verifies if an authentication token is configured.
func (f *Fixer) CheckAuthTokenSet() (bool, error) {
	f.Logger.Println("Checking if gateway authentication token is set")

	cmd := exec.Command("moltbot", "config", "get", "gateway.authToken")
	output, err := cmd.CombinedOutput()
	if err != nil {
		f.Logger.Println("Gateway authentication token is NOT set")
		return false, nil
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		f.Logger.Println("Gateway authentication token is empty")
		return false, nil
	}

	f.Logger.Println("Gateway authentication token is configured")
	return true, nil
}

// FixAll applies all gateway security fixes.
func (f *Fixer) FixAll() error {
	f.Logger.Println("Applying all gateway security fixes")

	// Force loopback binding
	if err := f.ForceLoopback(); err != nil {
		return fmt.Errorf("ForceLoopback failed: %w", err)
	}

	// Check and set auth token if not already set
	hasToken, err := f.CheckAuthTokenSet()
	if err != nil {
		return fmt.Errorf("CheckAuthTokenSet failed: %w", err)
	}

	if !hasToken {
		if _, err := f.SetAuthToken(); err != nil {
			return fmt.Errorf("SetAuthToken failed: %w", err)
		}
	}

	// Print logging recommendations
	f.FixStartupLogging()

	f.Logger.Println("All gateway security fixes applied successfully")
	return nil
}
