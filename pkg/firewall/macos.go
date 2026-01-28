package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// PFRule represents a macOS PF (Packet Filter) rule.
type PFRule struct {
	Action      string // pass, block
	Direction   string // in, out
	Quick       bool
	Interface   string
	Protocol    string
	Source      string
	Destination string
	Port        int
	Flags       string
	Label       string
}

// PFManager manages macOS PF firewall rules.
type PFManager struct {
	dryRun     bool
	anchorName string
}

// NewPFManager creates a new PF manager.
func NewPFManager(dryRun bool) *PFManager {
	return &PFManager{
		dryRun:     dryRun,
		anchorName: "com.moltbot.hardener",
	}
}

// IsAvailable checks if pfctl is available on the system.
func (m *PFManager) IsAvailable() bool {
	_, err := exec.LookPath("pfctl")
	return err == nil
}

// IsEnabled checks if PF is enabled.
func (m *PFManager) IsEnabled() (bool, error) {
	cmd := exec.Command("pfctl", "-s", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// pfctl requires root, check if it's just a permission issue
		if strings.Contains(string(output), "Permission denied") {
			return false, fmt.Errorf("permission denied: pfctl requires root privileges")
		}
		return false, fmt.Errorf("failed to check PF status: %w", err)
	}

	return strings.Contains(string(output), "Status: Enabled"), nil
}

// Enable enables PF.
func (m *PFManager) Enable() error {
	if m.dryRun {
		fmt.Println("[DRY RUN] pfctl -e")
		return nil
	}

	cmd := exec.Command("pfctl", "-e")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore "already enabled" error
		if !strings.Contains(string(output), "already enabled") {
			return fmt.Errorf("failed to enable PF: %w, output: %s", err, output)
		}
	}

	return nil
}

// Disable disables PF.
func (m *PFManager) Disable() error {
	if m.dryRun {
		fmt.Println("[DRY RUN] pfctl -d")
		return nil
	}

	cmd := exec.Command("pfctl", "-d")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable PF: %w, output: %s", err, output)
	}

	return nil
}

// ListRules returns all current PF rules.
func (m *PFManager) ListRules() ([]PFRule, error) {
	cmd := exec.Command("pfctl", "-s", "rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "Permission denied") {
			return nil, fmt.Errorf("permission denied: pfctl requires root privileges")
		}
		return nil, fmt.Errorf("failed to list PF rules: %w", err)
	}

	return m.parseRules(string(output))
}

// parseRules parses pfctl output into structured rules.
func (m *PFManager) parseRules(output string) ([]PFRule, error) {
	var rules []PFRule
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Simplified rule parsing regex
	ruleRegex := regexp.MustCompile(`^(pass|block)\s+(in|out)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !ruleRegex.MatchString(line) {
			continue
		}

		rule := m.parseRule(line)
		rules = append(rules, rule)
	}

	return rules, scanner.Err()
}

// parseRule parses a single PF rule line.
func (m *PFManager) parseRule(line string) PFRule {
	rule := PFRule{}
	parts := strings.Fields(line)

	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "pass":
			rule.Action = "pass"
		case "block":
			rule.Action = "block"
		case "in":
			rule.Direction = "in"
		case "out":
			rule.Direction = "out"
		case "quick":
			rule.Quick = true
		case "on":
			if i+1 < len(parts) {
				rule.Interface = parts[i+1]
				i++
			}
		case "proto":
			if i+1 < len(parts) {
				rule.Protocol = parts[i+1]
				i++
			}
		case "from":
			if i+1 < len(parts) {
				rule.Source = parts[i+1]
				i++
			}
		case "to":
			if i+1 < len(parts) {
				rule.Destination = parts[i+1]
				i++
			}
		case "port":
			if i+1 < len(parts) {
				if port, err := strconv.Atoi(parts[i+1]); err == nil {
					rule.Port = port
				}
				i++
			}
		case "label":
			if i+1 < len(parts) {
				rule.Label = strings.Trim(parts[i+1], "\"")
				i++
			}
		}
	}

	return rule
}

// AddAnchor adds the Moltbot anchor to the main PF configuration.
func (m *PFManager) AddAnchor() error {
	if m.dryRun {
		fmt.Printf("[DRY RUN] Adding anchor %s to pf.conf\n", m.anchorName)
		return nil
	}

	// Check if anchor already exists in pf.conf
	checkCmd := exec.Command("grep", "-q", m.anchorName, "/etc/pf.conf")
	if err := checkCmd.Run(); err == nil {
		// Anchor reference already exists
		return nil
	}

	// Add anchor reference to pf.conf
	anchorLine := fmt.Sprintf("\nanchor \"%s\"\nload anchor \"%s\" from \"/etc/pf.anchors/%s\"\n",
		m.anchorName, m.anchorName, m.anchorName)

	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("echo '%s' | sudo tee -a /etc/pf.conf", anchorLine))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add anchor to pf.conf: %w, output: %s", err, output)
	}

	return nil
}

// WriteAnchorRules writes rules to the Moltbot anchor file.
func (m *PFManager) WriteAnchorRules(rules []PFRule) error {
	anchorPath := fmt.Sprintf("/etc/pf.anchors/%s", m.anchorName)

	var ruleLines []string
	for _, rule := range rules {
		ruleLines = append(ruleLines, m.formatRule(rule))
	}

	content := strings.Join(ruleLines, "\n") + "\n"

	if m.dryRun {
		fmt.Printf("[DRY RUN] Writing to %s:\n%s\n", anchorPath, content)
		return nil
	}

	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("echo '%s' | sudo tee %s", content, anchorPath))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to write anchor rules: %w, output: %s", err, output)
	}

	return nil
}

// formatRule formats a PFRule as a pf.conf rule string.
func (m *PFManager) formatRule(rule PFRule) string {
	var parts []string

	parts = append(parts, rule.Action)

	if rule.Direction != "" {
		parts = append(parts, rule.Direction)
	}

	if rule.Quick {
		parts = append(parts, "quick")
	}

	if rule.Interface != "" {
		parts = append(parts, "on", rule.Interface)
	}

	if rule.Protocol != "" {
		parts = append(parts, "proto", rule.Protocol)
	}

	if rule.Source != "" {
		parts = append(parts, "from", rule.Source)
	} else {
		parts = append(parts, "from", "any")
	}

	if rule.Destination != "" {
		parts = append(parts, "to", rule.Destination)
	} else {
		parts = append(parts, "to", "any")
	}

	if rule.Port > 0 {
		parts = append(parts, "port", strconv.Itoa(rule.Port))
	}

	if rule.Label != "" {
		parts = append(parts, "label", fmt.Sprintf("\"%s\"", rule.Label))
	}

	return strings.Join(parts, " ")
}

// ReloadRules reloads PF rules from configuration.
func (m *PFManager) ReloadRules() error {
	if m.dryRun {
		fmt.Println("[DRY RUN] pfctl -f /etc/pf.conf")
		return nil
	}

	cmd := exec.Command("pfctl", "-f", "/etc/pf.conf")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload PF rules: %w, output: %s", err, output)
	}

	return nil
}

// RestrictGatewayPort restricts the Moltbot gateway port to localhost only.
func (m *PFManager) RestrictGatewayPort(port int) error {
	rules := []PFRule{
		// Allow localhost
		{
			Action:    "pass",
			Direction: "in",
			Quick:     true,
			Protocol:  "tcp",
			Source:    "127.0.0.1",
			Port:      port,
			Label:     "moltbot-gateway-localhost",
		},
		// Block external
		{
			Action:    "block",
			Direction: "in",
			Quick:     true,
			Protocol:  "tcp",
			Port:      port,
			Label:     "moltbot-gateway-block-external",
		},
	}

	if err := m.WriteAnchorRules(rules); err != nil {
		return err
	}

	return m.ReloadRules()
}

// BlockDangerousOutbound blocks commonly dangerous outbound connections.
func (m *PFManager) BlockDangerousOutbound() error {
	dangerousPorts := []struct {
		port  int
		label string
	}{
		{4444, "moltbot-block-metasploit"},
		{5555, "moltbot-block-android-debug"},
		{6666, "moltbot-block-irc-backdoor"},
		{6667, "moltbot-block-irc"},
		{31337, "moltbot-block-backorifice"},
	}

	var rules []PFRule
	for _, dp := range dangerousPorts {
		rules = append(rules, PFRule{
			Action:    "block",
			Direction: "out",
			Quick:     true,
			Protocol:  "tcp",
			Port:      dp.port,
			Label:     dp.label,
		})
	}

	if err := m.WriteAnchorRules(rules); err != nil {
		return err
	}

	return m.ReloadRules()
}

// AppFirewall manages the macOS Application Firewall (socketfilterfw).
type AppFirewall struct {
	dryRun bool
}

// NewAppFirewall creates a new Application Firewall manager.
func NewAppFirewall(dryRun bool) *AppFirewall {
	return &AppFirewall{dryRun: dryRun}
}

// IsAvailable checks if socketfilterfw is available.
func (f *AppFirewall) IsAvailable() bool {
	_, err := exec.LookPath("/usr/libexec/ApplicationFirewall/socketfilterfw")
	return err == nil
}

// IsEnabled checks if the application firewall is enabled.
func (f *AppFirewall) IsEnabled() (bool, error) {
	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check application firewall status: %w", err)
	}

	return strings.Contains(string(output), "enabled"), nil
}

// Enable enables the application firewall.
func (f *AppFirewall) Enable() error {
	if f.dryRun {
		fmt.Println("[DRY RUN] socketfilterfw --setglobalstate on")
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable application firewall: %w, output: %s", err, output)
	}

	return nil
}

// Disable disables the application firewall.
func (f *AppFirewall) Disable() error {
	if f.dryRun {
		fmt.Println("[DRY RUN] socketfilterfw --setglobalstate off")
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable application firewall: %w, output: %s", err, output)
	}

	return nil
}

// BlockAllIncoming sets the firewall to block all incoming connections.
func (f *AppFirewall) BlockAllIncoming() error {
	if f.dryRun {
		fmt.Println("[DRY RUN] socketfilterfw --setblockall on")
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setblockall", "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to block all incoming: %w, output: %s", err, output)
	}

	return nil
}

// AllowSignedApps allows signed applications to receive incoming connections.
func (f *AppFirewall) AllowSignedApps() error {
	if f.dryRun {
		fmt.Println("[DRY RUN] socketfilterfw --setallowsigned on")
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setallowsigned", "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow signed apps: %w, output: %s", err, output)
	}

	return nil
}

// EnableStealthMode enables stealth mode (don't respond to ping, etc.).
func (f *AppFirewall) EnableStealthMode() error {
	if f.dryRun {
		fmt.Println("[DRY RUN] socketfilterfw --setstealthmode on")
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable stealth mode: %w, output: %s", err, output)
	}

	return nil
}

// IsStealthModeEnabled checks if stealth mode is enabled.
func (f *AppFirewall) IsStealthModeEnabled() (bool, error) {
	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check stealth mode: %w", err)
	}

	return strings.Contains(string(output), "enabled"), nil
}

// AddAppException adds an application to the firewall allow list.
func (f *AppFirewall) AddAppException(appPath string) error {
	if f.dryRun {
		fmt.Printf("[DRY RUN] socketfilterfw --add %s\n", appPath)
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add", appPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add app exception: %w, output: %s", err, output)
	}

	return nil
}

// RemoveAppException removes an application from the firewall allow list.
func (f *AppFirewall) RemoveAppException(appPath string) error {
	if f.dryRun {
		fmt.Printf("[DRY RUN] socketfilterfw --remove %s\n", appPath)
		return nil
	}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove", appPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove app exception: %w, output: %s", err, output)
	}

	return nil
}

// ListApps lists all applications in the firewall.
func (f *AppFirewall) ListApps() ([]string, error) {
	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list apps: %w", err)
	}

	var apps []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "/") {
			apps = append(apps, line)
		}
	}

	return apps, scanner.Err()
}

// GetAppState gets the state of an application in the firewall.
func (f *AppFirewall) GetAppState(appPath string) (string, error) {
	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getappblocked", appPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get app state: %w", err)
	}

	if strings.Contains(string(output), "BLOCK") {
		return "blocked", nil
	} else if strings.Contains(string(output), "ALLOW") {
		return "allowed", nil
	}

	return "unknown", nil
}
