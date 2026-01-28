package audit

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.registry == nil {
		t.Error("Scanner registry is nil")
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}

	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.expected {
			t.Errorf("Severity.String() = %s, want %s", got, tt.expected)
		}
	}
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity Severity
		wantLen  int // Color should be non-empty hex string
	}{
		{SeverityInfo, 7},
		{SeverityLow, 7},
		{SeverityMedium, 7},
		{SeverityHigh, 7},
		{SeverityCritical, 7},
	}

	for _, tt := range tests {
		color := tt.severity.Color()
		if len(color) != tt.wantLen {
			t.Errorf("Severity(%d).Color() = %s, want len %d", tt.severity, color, tt.wantLen)
		}
	}
}

func TestAuditFindingStruct(t *testing.T) {
	finding := AuditFinding{
		CheckID:     "TEST-001",
		Severity:    SeverityHigh,
		Title:       "Test Finding",
		Description: "This is a test",
		File:        "/test/path",
		Line:        42,
		Remediation: "Fix it",
		AutoFixable: true,
		Fixed:       false,
	}

	if finding.CheckID != "TEST-001" {
		t.Error("CheckID mismatch")
	}
	if finding.Severity != SeverityHigh {
		t.Error("Severity mismatch")
	}
	if !finding.AutoFixable {
		t.Error("AutoFixable should be true")
	}
}

func TestScanResultSummary(t *testing.T) {
	result := &ScanResult{
		Findings: []AuditFinding{
			{CheckID: "A", Severity: SeverityCritical},
			{CheckID: "B", Severity: SeverityHigh},
			{CheckID: "C", Severity: SeverityMedium},
			{CheckID: "D", Severity: SeverityLow},
			{CheckID: "E", Severity: SeverityInfo},
		},
	}

	summary := result.Summary()

	if summary[SeverityCritical] != 1 {
		t.Errorf("Critical count: got %d, want 1", summary[SeverityCritical])
	}
	if summary[SeverityHigh] != 1 {
		t.Errorf("High count: got %d, want 1", summary[SeverityHigh])
	}
	if summary[SeverityMedium] != 1 {
		t.Errorf("Medium count: got %d, want 1", summary[SeverityMedium])
	}
	if summary[SeverityLow] != 1 {
		t.Errorf("Low count: got %d, want 1", summary[SeverityLow])
	}
}

func TestScanResultHasCritical(t *testing.T) {
	withCritical := &ScanResult{
		Findings: []AuditFinding{
			{Severity: SeverityCritical},
		},
	}
	if !withCritical.HasCritical() {
		t.Error("HasCritical should return true")
	}

	withoutCritical := &ScanResult{
		Findings: []AuditFinding{
			{Severity: SeverityHigh},
		},
	}
	if withoutCritical.HasCritical() {
		t.Error("HasCritical should return false")
	}
}

func TestScanResultHasHigh(t *testing.T) {
	withHigh := &ScanResult{
		Findings: []AuditFinding{
			{Severity: SeverityHigh},
		},
	}
	if !withHigh.HasHigh() {
		t.Error("HasHigh should return true")
	}

	withoutHigh := &ScanResult{
		Findings: []AuditFinding{
			{Severity: SeverityLow},
		},
	}
	if withoutHigh.HasHigh() {
		t.Error("HasHigh should return false")
	}
}

func TestScanResultFixableCount(t *testing.T) {
	result := &ScanResult{
		Findings: []AuditFinding{
			{AutoFixable: true, Fixed: false},
			{AutoFixable: true, Fixed: true},
			{AutoFixable: false, Fixed: false},
		},
	}

	count := result.FixableCount()
	if count != 1 {
		t.Errorf("FixableCount: got %d, want 1", count)
	}
}

func TestCheckCategories(t *testing.T) {
	categories := []Category{
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

	for _, cat := range categories {
		if cat == "" {
			t.Error("Empty category found")
		}
	}
}

func TestCheckRegistry(t *testing.T) {
	registry := NewCheckRegistry()

	check := &CheckDefinition{
		ID:       "TEST-001",
		Title:    "Test Check",
		Category: CategoryConfig,
		Severity: SeverityMedium,
	}

	registry.Register(check)

	// Test Get
	got, ok := registry.Get("TEST-001")
	if !ok {
		t.Error("Check not found after registration")
	}
	if got.Title != "Test Check" {
		t.Errorf("Title mismatch: got %s, want Test Check", got.Title)
	}

	// Test All
	all := registry.All()
	if len(all) != 1 {
		t.Errorf("All() returned %d checks, want 1", len(all))
	}

	// Test ByCategory
	byCategory := registry.ByCategory(CategoryConfig)
	if len(byCategory) != 1 {
		t.Errorf("ByCategory returned %d checks, want 1", len(byCategory))
	}

	// Test non-existent category
	byOther := registry.ByCategory(CategoryCredentials)
	if len(byOther) != 0 {
		t.Errorf("ByCategory should return 0 for non-existent category")
	}
}

func TestScanConfig(t *testing.T) {
	cfg := ScanConfig{
		MoltbotConfigPath: "/tmp/test",
		GatewayPort:       18789,
		GatewayMode:       "loopback",
		DockerEnabled:     true,
		Platform:          "darwin",
		HomeDir:           "/Users/test",
		Verbose:           true,
	}

	if cfg.MoltbotConfigPath != "/tmp/test" {
		t.Error("MoltbotConfigPath mismatch")
	}
	if cfg.GatewayPort != 18789 {
		t.Error("GatewayPort mismatch")
	}
}
