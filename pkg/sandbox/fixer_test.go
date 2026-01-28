package sandbox

import (
	"testing"
)

func TestNewFixer(t *testing.T) {
	fixer := NewFixer(false)
	if fixer == nil {
		t.Fatal("NewFixer returned nil")
	}
	if fixer.DryRun != false {
		t.Error("DryRun should be false")
	}
}

func TestNewFixerDryRun(t *testing.T) {
	fixer := NewFixer(true)
	if fixer == nil {
		t.Fatal("NewFixer returned nil")
	}
	if fixer.DryRun != true {
		t.Error("DryRun should be true")
	}
}

func TestEnableSandboxDryRun(t *testing.T) {
	fixer := NewFixer(true)

	err := fixer.EnableSandbox()
	if err != nil {
		t.Errorf("EnableSandbox in dry-run should not fail: %v", err)
	}
}

func TestSetNetworkNoneDryRun(t *testing.T) {
	fixer := NewFixer(true)

	err := fixer.SetNetworkNone()
	if err != nil {
		t.Errorf("SetNetworkNone in dry-run should not fail: %v", err)
	}
}

func TestDropAllCapsDryRun(t *testing.T) {
	fixer := NewFixer(true)

	err := fixer.DropAllCaps()
	if err != nil {
		t.Errorf("DropAllCaps in dry-run should not fail: %v", err)
	}
}

func TestDisableHostControlDryRun(t *testing.T) {
	fixer := NewFixer(true)

	err := fixer.DisableHostControl()
	if err != nil {
		t.Errorf("DisableHostControl in dry-run should not fail: %v", err)
	}
}

func TestDangerousMountStruct(t *testing.T) {
	mount := DangerousMount{
		Path:   "/var/run/docker.sock",
		Reason: "Docker socket access",
		Risk:   "critical",
	}

	if mount.Path != "/var/run/docker.sock" {
		t.Error("Path mismatch")
	}
	if mount.Risk != "critical" {
		t.Error("Risk mismatch")
	}
}

func TestValidateBindMountsMoltbotNotInstalled(t *testing.T) {
	fixer := NewFixer(true)

	// When moltbot is not installed, should return nil (no mounts configured)
	dangerous, err := fixer.ValidateBindMounts()
	if err != nil {
		t.Logf("ValidateBindMounts returned error (expected): %v", err)
	}
	if dangerous != nil && len(dangerous) > 0 {
		t.Logf("Found dangerous mounts: %v", dangerous)
	}
}

func TestRestrictSetupCommandMoltbotNotInstalled(t *testing.T) {
	fixer := NewFixer(true)

	warnings, err := fixer.RestrictSetupCommand()
	if err != nil {
		t.Logf("RestrictSetupCommand returned error (expected): %v", err)
	}
	if warnings != nil && len(warnings) > 0 {
		t.Logf("Found warnings: %v", warnings)
	}
}

func TestGetSandboxStatusMoltbotNotInstalled(t *testing.T) {
	fixer := NewFixer(true)

	status, err := fixer.GetSandboxStatus()
	if err != nil {
		t.Logf("GetSandboxStatus returned error (expected): %v", err)
	}

	// Should return status map even if values are "(not set)"
	if status == nil {
		t.Error("Status should not be nil")
	}

	t.Logf("Sandbox status: %+v", status)
}

func TestFixAllDryRun(t *testing.T) {
	fixer := NewFixer(true)

	err := fixer.FixAll()
	if err != nil {
		t.Logf("FixAll in dry-run: %v (expected if moltbot not installed)", err)
	}
}

// Unit tests for dangerous mount patterns (these don't require moltbot)
func TestDangerousMountPatterns(t *testing.T) {
	dangerousPaths := []string{
		"/",
		"/etc",
		"/etc/passwd",
		"/etc/shadow",
		"/root",
		"/home",
		"/var/run/docker.sock",
		"/proc",
		"/sys",
		"/dev",
		"~/.ssh",
		"~/.aws",
		"~/.clawdbot",
	}

	// Just verify the paths are in the expected format
	for _, path := range dangerousPaths {
		if path == "" {
			t.Error("Empty dangerous path found")
		}
	}
}

// Test dangerous patterns for setup commands
func TestDangerousCommandPatterns(t *testing.T) {
	dangerousPatterns := []string{
		"curl",
		"wget",
		"chmod +x",
		"sudo",
		"apt install",
		"pip install",
		"npm install -g",
		"eval",
		"bash -c",
		"sh -c",
	}

	// Just verify patterns are defined
	for _, pattern := range dangerousPatterns {
		if pattern == "" {
			t.Error("Empty dangerous pattern found")
		}
	}
}
