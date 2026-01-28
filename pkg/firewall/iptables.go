// Package firewall provides firewall management utilities for Linux and macOS.
package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// IPTablesRule represents an iptables firewall rule.
type IPTablesRule struct {
	Chain       string
	Protocol    string
	Source      string
	Destination string
	Port        int
	Action      string
	Comment     string
}

// IPTablesManager manages iptables firewall rules on Linux.
type IPTablesManager struct {
	dryRun bool
}

// NewIPTablesManager creates a new iptables manager.
func NewIPTablesManager(dryRun bool) *IPTablesManager {
	return &IPTablesManager{dryRun: dryRun}
}

// IsAvailable checks if iptables is available on the system.
func (m *IPTablesManager) IsAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

// ListRules returns all current iptables rules.
func (m *IPTablesManager) ListRules() ([]IPTablesRule, error) {
	cmd := exec.Command("iptables", "-L", "-n", "-v", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list iptables rules: %w", err)
	}

	return m.parseRules(string(output))
}

// parseRules parses iptables output into structured rules.
func (m *IPTablesManager) parseRules(output string) ([]IPTablesRule, error) {
	var rules []IPTablesRule
	var currentChain string

	scanner := bufio.NewScanner(strings.NewReader(output))
	chainRegex := regexp.MustCompile(`^Chain (\w+)`)

	for scanner.Scan() {
		line := scanner.Text()

		// Check for chain header
		if matches := chainRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentChain = matches[1]
			continue
		}

		// Skip header lines and empty lines
		if strings.HasPrefix(line, "num") || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse rule line (simplified parsing)
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		rule := IPTablesRule{
			Chain:    currentChain,
			Protocol: fields[3],
			Source:   fields[7],
		}

		if len(fields) > 8 {
			rule.Destination = fields[8]
		}

		// Parse action from target field
		rule.Action = fields[2]

		rules = append(rules, rule)
	}

	return rules, scanner.Err()
}

// HasRule checks if a specific rule exists.
func (m *IPTablesManager) HasRule(chain, protocol, destination string, port int, action string) (bool, error) {
	rules, err := m.ListRules()
	if err != nil {
		return false, err
	}

	for _, rule := range rules {
		if rule.Chain == chain &&
			(protocol == "" || rule.Protocol == protocol) &&
			(destination == "" || rule.Destination == destination) &&
			(port == 0 || rule.Port == port) &&
			(action == "" || rule.Action == action) {
			return true, nil
		}
	}

	return false, nil
}

// AddRule adds a new iptables rule.
func (m *IPTablesManager) AddRule(rule IPTablesRule) error {
	args := []string{"-A", rule.Chain}

	if rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}

	if rule.Destination != "" {
		args = append(args, "-d", rule.Destination)
	}

	if rule.Port > 0 {
		args = append(args, "--dport", strconv.Itoa(rule.Port))
	}

	if rule.Comment != "" {
		args = append(args, "-m", "comment", "--comment", rule.Comment)
	}

	args = append(args, "-j", rule.Action)

	if m.dryRun {
		fmt.Printf("[DRY RUN] iptables %s\n", strings.Join(args, " "))
		return nil
	}

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add iptables rule: %w, output: %s", err, output)
	}

	return nil
}

// DeleteRule removes an iptables rule.
func (m *IPTablesManager) DeleteRule(rule IPTablesRule) error {
	args := []string{"-D", rule.Chain}

	if rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}

	if rule.Destination != "" {
		args = append(args, "-d", rule.Destination)
	}

	if rule.Port > 0 {
		args = append(args, "--dport", strconv.Itoa(rule.Port))
	}

	args = append(args, "-j", rule.Action)

	if m.dryRun {
		fmt.Printf("[DRY RUN] iptables %s\n", strings.Join(args, " "))
		return nil
	}

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete iptables rule: %w, output: %s", err, output)
	}

	return nil
}

// BlockOutboundPort blocks outbound traffic on a specific port.
func (m *IPTablesManager) BlockOutboundPort(port int, protocol string, comment string) error {
	rule := IPTablesRule{
		Chain:    "OUTPUT",
		Protocol: protocol,
		Port:     port,
		Action:   "DROP",
		Comment:  comment,
	}
	return m.AddRule(rule)
}

// AllowInboundPort allows inbound traffic on a specific port from a source.
func (m *IPTablesManager) AllowInboundPort(port int, protocol string, source string, comment string) error {
	rule := IPTablesRule{
		Chain:    "INPUT",
		Protocol: protocol,
		Source:   source,
		Port:     port,
		Action:   "ACCEPT",
		Comment:  comment,
	}
	return m.AddRule(rule)
}

// RestrictGatewayPort restricts the Moltbot gateway port to localhost only.
func (m *IPTablesManager) RestrictGatewayPort(port int) error {
	// First, allow localhost
	if err := m.AllowInboundPort(port, "tcp", "127.0.0.1", "moltbot-gateway-localhost"); err != nil {
		return err
	}

	// Then block all other sources
	rule := IPTablesRule{
		Chain:    "INPUT",
		Protocol: "tcp",
		Port:     port,
		Action:   "DROP",
		Comment:  "moltbot-gateway-block-external",
	}
	return m.AddRule(rule)
}

// BlockDangerousOutbound blocks commonly dangerous outbound connections.
func (m *IPTablesManager) BlockDangerousOutbound() error {
	// Block common malware ports
	dangerousPorts := []struct {
		port    int
		proto   string
		comment string
	}{
		{4444, "tcp", "moltbot-block-metasploit-default"},
		{5555, "tcp", "moltbot-block-android-debug"},
		{6666, "tcp", "moltbot-block-irc-backdoor"},
		{6667, "tcp", "moltbot-block-irc"},
		{31337, "tcp", "moltbot-block-backorifice"},
	}

	for _, dp := range dangerousPorts {
		if err := m.BlockOutboundPort(dp.port, dp.proto, dp.comment); err != nil {
			return fmt.Errorf("failed to block port %d: %w", dp.port, err)
		}
	}

	return nil
}

// CheckGatewayExposure checks if the gateway port is exposed externally.
func (m *IPTablesManager) CheckGatewayExposure(port int) (bool, error) {
	// Check if there's an ACCEPT rule for the port from any source
	rules, err := m.ListRules()
	if err != nil {
		return false, err
	}

	for _, rule := range rules {
		if rule.Chain == "INPUT" &&
			rule.Port == port &&
			rule.Action == "ACCEPT" &&
			rule.Source != "127.0.0.1" &&
			rule.Source != "127.0.0.0/8" {
			return true, nil // Port is exposed
		}
	}

	return false, nil
}

// SaveRules persists iptables rules (Linux-specific).
func (m *IPTablesManager) SaveRules() error {
	if m.dryRun {
		fmt.Println("[DRY RUN] Saving iptables rules")
		return nil
	}

	// Try iptables-save
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to save iptables rules: %w", err)
	}

	// Write to standard location
	writeCmd := exec.Command("tee", "/etc/iptables/rules.v4")
	writeCmd.Stdin = strings.NewReader(string(output))
	if err := writeCmd.Run(); err != nil {
		// Try alternative location
		writeCmd = exec.Command("tee", "/etc/sysconfig/iptables")
		writeCmd.Stdin = strings.NewReader(string(output))
		if err := writeCmd.Run(); err != nil {
			return fmt.Errorf("failed to persist iptables rules: %w", err)
		}
	}

	return nil
}

// FlushChain removes all rules from a chain.
func (m *IPTablesManager) FlushChain(chain string) error {
	if m.dryRun {
		fmt.Printf("[DRY RUN] iptables -F %s\n", chain)
		return nil
	}

	cmd := exec.Command("iptables", "-F", chain)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush chain %s: %w, output: %s", chain, err, output)
	}

	return nil
}

// CreateMoltbotChain creates a dedicated chain for Moltbot rules.
func (m *IPTablesManager) CreateMoltbotChain() error {
	chainName := "MOLTBOT"

	if m.dryRun {
		fmt.Printf("[DRY RUN] iptables -N %s\n", chainName)
		return nil
	}

	// Create the chain (ignore error if it already exists)
	cmd := exec.Command("iptables", "-N", chainName)
	cmd.Run() // Ignore error - chain may already exist

	// Insert jump to MOLTBOT chain at the beginning of INPUT
	cmd = exec.Command("iptables", "-I", "INPUT", "1", "-j", chainName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Check if jump already exists
		checkCmd := exec.Command("iptables", "-C", "INPUT", "-j", chainName)
		if checkCmd.Run() != nil {
			return fmt.Errorf("failed to add jump to MOLTBOT chain: %w, output: %s", err, output)
		}
	}

	return nil
}
