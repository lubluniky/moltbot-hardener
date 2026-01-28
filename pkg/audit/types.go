// Package audit provides security scanning capabilities for moltbot configurations.
package audit

import (
	"time"
)

// Severity represents the severity level of an audit finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of a Severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Color returns the ANSI color code for the severity level.
func (s Severity) Color() string {
	switch s {
	case SeverityInfo:
		return "#7C8A9A" // gray
	case SeverityLow:
		return "#4A90D9" // blue
	case SeverityMedium:
		return "#F5A623" // yellow/orange
	case SeverityHigh:
		return "#E94D4D" // red
	case SeverityCritical:
		return "#9B2335" // dark red
	default:
		return "#FFFFFF"
	}
}

// Category represents the category of a security check.
type Category string

const (
	CategoryCredentials Category = "credentials"
	CategoryNetwork     Category = "network"
	CategoryPermissions Category = "permissions"
	CategoryGateway     Category = "gateway"
	CategoryDocker      Category = "docker"
	CategorySandbox     Category = "sandbox"
	CategoryPairing     Category = "pairing"
	CategoryConfig      Category = "config"
	CategoryDependency  Category = "dependency"
)

// AuditFinding represents a single security issue found during audit.
type AuditFinding struct {
	// CheckID is the unique identifier for this check (e.g., "CRED-001").
	CheckID string `json:"check_id"`

	// Severity indicates how critical the finding is.
	Severity Severity `json:"severity"`

	// Title is a short description of the issue.
	Title string `json:"title"`

	// Description provides detailed information about the vulnerability.
	Description string `json:"description"`

	// Category groups related checks together.
	Category Category `json:"category"`

	// File is the path to the affected file, if applicable.
	File string `json:"file,omitempty"`

	// Line is the line number in the file, if applicable.
	Line int `json:"line,omitempty"`

	// Remediation describes how to fix the issue.
	Remediation string `json:"remediation"`

	// AutoFixable indicates whether this issue can be automatically fixed.
	AutoFixable bool `json:"auto_fixable"`

	// Fixed indicates whether this issue has been remediated.
	Fixed bool `json:"fixed"`

	// FixedAt records when the issue was fixed.
	FixedAt *time.Time `json:"fixed_at,omitempty"`

	// Evidence contains details that led to this finding.
	Evidence string `json:"evidence,omitempty"`

	// References contains URLs to relevant documentation.
	References []string `json:"references,omitempty"`
}

// ScanConfig holds configuration for the security scanner.
type ScanConfig struct {
	// MoltbotConfigPath is the path to the moltbot configuration directory.
	MoltbotConfigPath string `json:"moltbot_config_path"`

	// CredentialsPath is the path to the credentials directory.
	CredentialsPath string `json:"credentials_path"`

	// SessionsPath is the path to the sessions directory.
	SessionsPath string `json:"sessions_path"`

	// GatewayPort is the port the gateway listens on.
	GatewayPort int `json:"gateway_port"`

	// GatewayMode is the gateway binding mode (local, lan, public).
	GatewayMode string `json:"gateway_mode"`

	// DockerEnabled indicates whether Docker sandboxing is enabled.
	DockerEnabled bool `json:"docker_enabled"`

	// Platform is the detected operating system (darwin, linux).
	Platform string `json:"platform"`

	// HomeDir is the user's home directory.
	HomeDir string `json:"home_dir"`

	// Verbose enables detailed output during scanning.
	Verbose bool `json:"verbose"`

	// SkipChecks is a list of check IDs to skip.
	SkipChecks []string `json:"skip_checks,omitempty"`

	// OnlyChecks limits scanning to these check IDs only.
	OnlyChecks []string `json:"only_checks,omitempty"`
}

// ScanResult contains the complete results of a security audit.
type ScanResult struct {
	// Findings is the list of all security issues found.
	Findings []AuditFinding `json:"findings"`

	// ScanStarted is when the scan began.
	ScanStarted time.Time `json:"scan_started"`

	// ScanCompleted is when the scan finished.
	ScanCompleted time.Time `json:"scan_completed"`

	// Platform is the detected operating system.
	Platform string `json:"platform"`

	// TotalChecks is the number of checks performed.
	TotalChecks int `json:"total_checks"`

	// PassedChecks is the number of checks that passed.
	PassedChecks int `json:"passed_checks"`

	// FailedChecks is the number of checks that failed.
	FailedChecks int `json:"failed_checks"`

	// SkippedChecks is the number of checks that were skipped.
	SkippedChecks int `json:"skipped_checks"`
}

// Summary returns a summary of findings by severity.
func (r *ScanResult) Summary() map[Severity]int {
	summary := make(map[Severity]int)
	for _, f := range r.Findings {
		summary[f.Severity]++
	}
	return summary
}

// HasCritical returns true if there are any critical findings.
func (r *ScanResult) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHigh returns true if there are any high severity findings.
func (r *ScanResult) HasHigh() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// FixableCount returns the number of findings that can be auto-fixed.
func (r *ScanResult) FixableCount() int {
	count := 0
	for _, f := range r.Findings {
		if f.AutoFixable && !f.Fixed {
			count++
		}
	}
	return count
}

// CheckDefinition defines metadata for a security check.
type CheckDefinition struct {
	// ID is the unique identifier (e.g., "CRED-001").
	ID string

	// Title is a short description.
	Title string

	// Description provides detailed information.
	Description string

	// Category groups related checks.
	Category Category

	// Severity is the default severity level.
	Severity Severity

	// Platforms limits the check to specific platforms (empty = all).
	Platforms []string

	// Remediation describes how to fix issues found by this check.
	Remediation string

	// AutoFixable indicates whether issues can be automatically fixed.
	AutoFixable bool

	// References contains URLs to relevant documentation.
	References []string

	// CheckFunc is the function that performs the actual check.
	CheckFunc CheckFunc
}

// CheckFunc is the signature for check functions.
type CheckFunc func(cfg *ScanConfig) ([]AuditFinding, error)

// CheckRegistry holds all registered security checks.
type CheckRegistry struct {
	checks map[string]*CheckDefinition
}

// NewCheckRegistry creates a new empty check registry.
func NewCheckRegistry() *CheckRegistry {
	return &CheckRegistry{
		checks: make(map[string]*CheckDefinition),
	}
}

// Register adds a check to the registry.
func (r *CheckRegistry) Register(check *CheckDefinition) {
	r.checks[check.ID] = check
}

// Get retrieves a check by ID.
func (r *CheckRegistry) Get(id string) (*CheckDefinition, bool) {
	check, ok := r.checks[id]
	return check, ok
}

// All returns all registered checks.
func (r *CheckRegistry) All() []*CheckDefinition {
	checks := make([]*CheckDefinition, 0, len(r.checks))
	for _, check := range r.checks {
		checks = append(checks, check)
	}
	return checks
}

// ByCategory returns checks filtered by category.
func (r *CheckRegistry) ByCategory(cat Category) []*CheckDefinition {
	var checks []*CheckDefinition
	for _, check := range r.checks {
		if check.Category == cat {
			checks = append(checks, check)
		}
	}
	return checks
}

// FixResult represents the result of attempting to fix a finding.
type FixResult struct {
	// Finding is the original finding that was fixed.
	Finding *AuditFinding

	// Success indicates whether the fix was applied successfully.
	Success bool

	// Message provides details about the fix attempt.
	Message string

	// BackupPath is the path to any backup created during the fix.
	BackupPath string
}
