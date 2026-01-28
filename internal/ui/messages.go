// Package ui provides terminal user interface components for moltbot-hardener.
package ui

import (
	"time"
)

// Severity levels for vulnerabilities.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
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

// Vulnerability represents a security issue found during scanning.
type Vulnerability struct {
	ID          string
	Title       string
	Description string
	Severity    Severity
	Category    string
	CanAutoFix  bool
	Fixed       bool
	Fixing      bool
}

// DependencyCheck represents the status of a dependency check.
type DependencyCheck struct {
	Name     string
	Required bool
	Found    bool
	Version  string
	Error    string
}

// ScanResult contains the results of a security scan.
type ScanResult struct {
	Vulnerabilities []Vulnerability
	Duration        time.Duration
	TotalChecks     int
	PassedChecks    int
}

// FixResult contains the result of fixing a vulnerability.
type FixResult struct {
	VulnerabilityID string
	Success         bool
	Error           string
}

// --- Bubbletea Messages ---

// StartScanMsg triggers the vulnerability scan.
type StartScanMsg struct{}

// ScanProgressMsg updates scan progress.
type ScanProgressMsg struct {
	Current int
	Total   int
	Message string
}

// ScanCompleteMsg signals scan completion.
type ScanCompleteMsg struct {
	Result ScanResult
}

// DependencyCheckMsg updates dependency check status.
type DependencyCheckMsg struct {
	Check DependencyCheck
}

// DependencyCheckCompleteMsg signals all dependency checks are done.
type DependencyCheckCompleteMsg struct {
	AllFound bool
	Missing  []string
}

// StartFixMsg triggers fixing of vulnerabilities.
type StartFixMsg struct {
	VulnerabilityIDs []string
}

// FixProgressMsg updates fix progress.
type FixProgressMsg struct {
	VulnerabilityID string
	Status          string
}

// FixCompleteMsg signals a fix is complete.
type FixCompleteMsg struct {
	Result FixResult
}

// AllFixesCompleteMsg signals all fixes are done.
type AllFixesCompleteMsg struct {
	TotalFixed  int
	TotalFailed int
}

// TickMsg is sent periodically for animations.
type TickMsg time.Time

// KeyPressMsg represents a key press event.
type KeyPressMsg struct {
	Key string
}

// QuitMsg signals the TUI should quit.
type QuitMsg struct{}

// ErrorMsg represents an error that occurred.
type ErrorMsg struct {
	Error error
}

// NavigateMsg changes the current view/state.
type NavigateMsg struct {
	State AppState
}
