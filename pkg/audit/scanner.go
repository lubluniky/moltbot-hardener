package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"
)

// Scanner performs security audits on moltbot configurations.
type Scanner struct {
	registry *CheckRegistry
	config   *ScanConfig
}

// NewScanner creates a new security scanner with default configuration.
func NewScanner() *Scanner {
	registry := NewCheckRegistry()
	RegisterAllChecks(registry)

	homeDir, _ := os.UserHomeDir()

	return &Scanner{
		registry: registry,
		config: &ScanConfig{
			MoltbotConfigPath: filepath.Join(homeDir, ".clawdbot"),
			CredentialsPath:   filepath.Join(homeDir, ".clawdbot", "credentials"),
			SessionsPath:      filepath.Join(homeDir, ".clawdbot", "sessions"),
			GatewayPort:       18789,
			GatewayMode:       "local",
			DockerEnabled:     false,
			Platform:          runtime.GOOS,
			HomeDir:           homeDir,
			Verbose:           false,
		},
	}
}

// NewScannerWithConfig creates a scanner with a custom configuration.
func NewScannerWithConfig(config *ScanConfig) *Scanner {
	registry := NewCheckRegistry()
	RegisterAllChecks(registry)

	return &Scanner{
		registry: registry,
		config:   config,
	}
}

// ScanConfig reads the moltbot configuration and updates the scanner config.
func (s *Scanner) ScanConfig() error {
	configPath := filepath.Join(s.config.MoltbotConfigPath, "config.json")
	content, err := os.ReadFile(configPath)
	if err != nil {
		// Config file doesn't exist, use defaults
		return nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return err
	}

	// Extract gateway configuration
	if gateway, ok := config["gateway"].(map[string]interface{}); ok {
		if port, ok := gateway["port"].(float64); ok {
			s.config.GatewayPort = int(port)
		}
		if mode, ok := gateway["mode"].(string); ok {
			s.config.GatewayMode = mode
		}
	}

	// Extract sandbox configuration
	if sandbox, ok := config["sandbox"].(map[string]interface{}); ok {
		if docker, ok := sandbox["docker"].(bool); ok {
			s.config.DockerEnabled = docker
		}
	}

	return nil
}

// Scan runs all registered security checks and returns the results.
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		ScanStarted: time.Now(),
		Platform:    s.config.Platform,
		Findings:    make([]AuditFinding, 0),
	}

	checks := s.registry.All()

	for _, check := range checks {
		// Skip if check is in skip list
		if len(s.config.SkipChecks) > 0 && slices.Contains(s.config.SkipChecks, check.ID) {
			result.SkippedChecks++
			continue
		}

		// Skip if not in only list (when only list is specified)
		if len(s.config.OnlyChecks) > 0 && !slices.Contains(s.config.OnlyChecks, check.ID) {
			result.SkippedChecks++
			continue
		}

		// Skip if platform doesn't match
		if len(check.Platforms) > 0 && !slices.Contains(check.Platforms, s.config.Platform) {
			result.SkippedChecks++
			continue
		}

		result.TotalChecks++

		findings, err := check.CheckFunc(s.config)
		if err != nil {
			// Log error but continue with other checks
			continue
		}

		if len(findings) > 0 {
			result.FailedChecks++
			result.Findings = append(result.Findings, findings...)
		} else {
			result.PassedChecks++
		}
	}

	result.ScanCompleted = time.Now()
	return result, nil
}

// ScanSingle runs a single security check by ID.
func (s *Scanner) ScanSingle(checkID string) (*ScanResult, error) {
	result := &ScanResult{
		ScanStarted: time.Now(),
		Platform:    s.config.Platform,
		Findings:    make([]AuditFinding, 0),
	}

	check, ok := s.registry.Get(checkID)
	if !ok {
		return result, nil
	}

	result.TotalChecks = 1

	findings, err := check.CheckFunc(s.config)
	if err != nil {
		return result, err
	}

	if len(findings) > 0 {
		result.FailedChecks = 1
		result.Findings = findings
	} else {
		result.PassedChecks = 1
	}

	result.ScanCompleted = time.Now()
	return result, nil
}

// ScanByCategory runs all checks in a specific category.
func (s *Scanner) ScanByCategory(category Category) (*ScanResult, error) {
	result := &ScanResult{
		ScanStarted: time.Now(),
		Platform:    s.config.Platform,
		Findings:    make([]AuditFinding, 0),
	}

	checks := s.registry.ByCategory(category)

	for _, check := range checks {
		// Skip if platform doesn't match
		if len(check.Platforms) > 0 && !slices.Contains(check.Platforms, s.config.Platform) {
			result.SkippedChecks++
			continue
		}

		result.TotalChecks++

		findings, err := check.CheckFunc(s.config)
		if err != nil {
			continue
		}

		if len(findings) > 0 {
			result.FailedChecks++
			result.Findings = append(result.Findings, findings...)
		} else {
			result.PassedChecks++
		}
	}

	result.ScanCompleted = time.Now()
	return result, nil
}

// GetConfig returns the current scanner configuration.
func (s *Scanner) GetConfig() *ScanConfig {
	return s.config
}

// SetVerbose enables or disables verbose output.
func (s *Scanner) SetVerbose(verbose bool) {
	s.config.Verbose = verbose
}

// SetSkipChecks sets the list of check IDs to skip.
func (s *Scanner) SetSkipChecks(ids []string) {
	s.config.SkipChecks = ids
}

// SetOnlyChecks limits scanning to specific check IDs.
func (s *Scanner) SetOnlyChecks(ids []string) {
	s.config.OnlyChecks = ids
}

// ListChecks returns all available check definitions.
func (s *Scanner) ListChecks() []*CheckDefinition {
	return s.registry.All()
}

// ListCategories returns all available categories.
func (s *Scanner) ListCategories() []Category {
	return []Category{
		CategoryCredentials,
		CategoryNetwork,
		CategoryPermissions,
		CategoryGateway,
		CategoryDocker,
		CategorySandbox,
		CategoryPairing,
		CategoryConfig,
		CategoryDependency,
	}
}

// DetectPlatform returns the current operating system.
func DetectPlatform() string {
	return runtime.GOOS
}

// IsMacOS returns true if running on macOS.
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// IsLinux returns true if running on Linux.
func IsLinux() bool {
	return runtime.GOOS == "linux"
}
