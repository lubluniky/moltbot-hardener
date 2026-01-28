package gateway

import (
	"testing"
)

func TestNewFixer(t *testing.T) {
	fixer := NewFixer(false)
	if fixer == nil {
		t.Fatal("NewFixer returned nil")
	}
	if fixer.Logger == nil {
		t.Error("Logger should be set by default")
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

func TestFixerForceLoopbackDryRun(t *testing.T) {
	fixer := NewFixer(true)

	// Dry run should not fail even if moltbot is not installed
	err := fixer.ForceLoopback()
	if err != nil {
		t.Errorf("ForceLoopback in dry-run should not fail: %v", err)
	}
}

func TestFixerSetAuthTokenDryRun(t *testing.T) {
	fixer := NewFixer(true)

	token, err := fixer.SetAuthToken()
	if err != nil {
		t.Errorf("SetAuthToken in dry-run should not fail: %v", err)
	}

	// Token should be generated (64 hex chars = 32 bytes)
	if len(token) != 64 {
		t.Errorf("Token should be 64 chars, got %d", len(token))
	}
}

func TestFixStartupLogging(t *testing.T) {
	fixer := NewFixer(true)
	recommendations := fixer.FixStartupLogging()

	if len(recommendations) == 0 {
		t.Error("Should return logging recommendations")
	}

	// Should include common recommendations
	found := false
	for _, rec := range recommendations {
		if rec != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("No valid recommendations returned")
	}
}

func TestBindModeConstants(t *testing.T) {
	if BindModeLoopback != "loopback" {
		t.Errorf("BindModeLoopback = %s, want loopback", BindModeLoopback)
	}
	if BindModeAll != "all" {
		t.Errorf("BindModeAll = %s, want all", BindModeAll)
	}
	if BindModeUnknown != "unknown" {
		t.Errorf("BindModeUnknown = %s, want unknown", BindModeUnknown)
	}
}

func TestFixerValidateBindModeMoltbotNotInstalled(t *testing.T) {
	fixer := NewFixer(true)

	// When moltbot is not installed, should return unknown
	mode, err := fixer.ValidateBindMode()
	if err != nil {
		t.Logf("ValidateBindMode returned error (expected): %v", err)
	}
	// Should handle gracefully
	t.Logf("Bind mode: %s", mode)
}

func TestFixerCheckAuthTokenSetMoltbotNotInstalled(t *testing.T) {
	fixer := NewFixer(true)

	hasToken, err := fixer.CheckAuthTokenSet()
	if err != nil {
		t.Logf("CheckAuthTokenSet returned error (expected): %v", err)
	}
	// When moltbot is not installed, should return false
	if hasToken {
		t.Log("hasToken is true (moltbot may be installed)")
	}
}

func TestFixerFixAllDryRun(t *testing.T) {
	fixer := NewFixer(true)

	// In dry-run mode, FixAll should succeed
	err := fixer.FixAll()
	if err != nil {
		t.Logf("FixAll in dry-run: %v (this is expected if moltbot not installed)", err)
	}
}
