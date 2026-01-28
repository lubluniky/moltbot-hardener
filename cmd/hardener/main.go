// Package main provides the entry point for the moltbot-hardener CLI.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/moltbot/moltbot-hardener/pkg/audit"
	"github.com/moltbot/moltbot-hardener/pkg/firewall"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Styles for colorful output
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7C3AED")).
			MarginBottom(1)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3B82F6"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))

	boldStyle = lipgloss.NewStyle().
			Bold(true)

	criticalStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#9B2335")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	highStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#EF4444")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	mediumStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#F59E0B")).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1)

	lowStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#3B82F6")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	infoSeverityStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#6B7280")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Padding(0, 1)
)

// CLI flags
var (
	verbose    bool
	jsonOutput bool
	skipChecks []string
	onlyChecks []string
	autoFix    bool
	dryRun     bool
	forceRun   bool // Force run even if bot is running
)

// isMoltbotRunning checks if moltbot gateway is currently running.
func isMoltbotRunning() bool {
	// First try official moltbot gateway status command
	cmd := exec.Command("moltbot", "gateway", "status", "--no-probe")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := strings.ToLower(string(output))
		if strings.Contains(outputStr, "running") || strings.Contains(outputStr, "active") {
			return true
		}
	}

	// Fallback: Check for moltbot gateway process directly
	patterns := []string{"moltbot-gateway", "moltbot gateway"}
	for _, pattern := range patterns {
		cmd := exec.Command("pgrep", "-f", pattern)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// On macOS, also check for Moltbot.app and launchd
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("pgrep", "-f", "Moltbot.app")
		if err := cmd.Run(); err == nil {
			return true
		}
		// Check launchd service
		cmd = exec.Command("launchctl", "print", fmt.Sprintf("gui/%d/bot.molt.gateway", os.Getuid()))
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	return false
}

// warnIfBotRunning displays a warning and asks for confirmation if the bot is running.
// Returns true if we should proceed, false if we should abort.
func warnIfBotRunning() bool {
	if !isMoltbotRunning() {
		fmt.Println(successStyle.Render("✓ Moltbot is not running - safe to apply fixes\n"))
		return true
	}

	// Bot is running - show warning
	fmt.Println()
	fmt.Println(errorStyle.Render("╔══════════════════════════════════════════════════════════════════╗"))
	fmt.Println(errorStyle.Render("║") + " " + warningStyle.Render("⚠️  WARNING: MOLTBOT IS CURRENTLY RUNNING") + "                          " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("╠══════════════════════════════════════════════════════════════════╣"))
	fmt.Println(errorStyle.Render("║") + "                                                                  " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "  " + boldStyle.Render("Applying fixes while bot is running is NOT recommended.") + "        " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "                                                                  " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "  Problems you may encounter:                                     " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "    • Gateway changes won't take effect until restart             " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "    • Sandbox settings won't apply to running agents              " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "    • Config files may be locked or overwritten                   " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "                                                                  " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "  " + successStyle.Render("Recommended:") + "                                                     " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "    1. Stop gateway:  " + infoStyle.Render("moltbot gateway stop") + "                        " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "    2. Run hardener:  " + infoStyle.Render("./hardener apply") + "                            " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "    3. Start gateway: " + infoStyle.Render("moltbot gateway start") + "                       " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("║") + "                                                                  " + errorStyle.Render("║"))
	fmt.Println(errorStyle.Render("╚══════════════════════════════════════════════════════════════════╝"))
	fmt.Println()

	if forceRun {
		fmt.Println(warningStyle.Render("--force specified, continuing anyway..."))
		return true
	}

	if autoFix {
		fmt.Println(errorStyle.Render("Bot is running. Use --force to continue, or stop the bot first."))
		return false
	}

	// Interactive mode - ask user
	fmt.Print(warningStyle.Render("Do you want to continue anyway? [y/N]: "))
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response == "y" || response == "yes" {
		fmt.Println(warningStyle.Render("Continuing with bot running - some fixes may not take effect"))
		return true
	}

	fmt.Println(infoStyle.Render("Aborted. Stop moltbot and run again."))
	return false
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, errorStyle.Render(err.Error()))
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "hardener",
	Short: "Security hardening tool for Moltbot",
	Long: `Moltbot Hardener scans, detects, and fixes security vulnerabilities
in your Moltbot installation.

Run without arguments to start the interactive TUI.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInteractiveTUI()
	},
}

// Audit command - scan for security vulnerabilities
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scan for security vulnerabilities",
	Long:  "Scan your moltbot configuration for security vulnerabilities and misconfigurations.",
	RunE:  runAudit,
}

// Apply command - apply security fixes
var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply security fixes",
	Long:  "Apply automatic security fixes for identified vulnerabilities.",
	RunE:  runApply,
}

// Fix command - fix a specific vulnerability
var fixCmd = &cobra.Command{
	Use:   "fix [check-id]",
	Short: "Fix a specific vulnerability",
	Long:  "Fix a specific security vulnerability by check ID.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runFix,
}

// Check-deps command - check dependencies for vulnerabilities
var checkDepsCmd = &cobra.Command{
	Use:   "check-deps",
	Short: "Check dependencies for vulnerabilities",
	Long:  "Check moltbot and extension dependencies for known vulnerabilities.",
	RunE:  runCheckDeps,
}

// List command - list all security checks
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all security checks",
	Long:  "List all available security checks with their descriptions.",
	Run:   runList,
}

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Firewall management commands",
}

var firewallStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check firewall status",
	RunE: func(cmd *cobra.Command, args []string) error {
		switch runtime.GOOS {
		case "darwin":
			return checkMacOSFirewallStatus()
		case "linux":
			return checkLinuxFirewallStatus()
		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	},
}

var firewallHardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Apply firewall hardening rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		dryRunFlag, _ := cmd.Flags().GetBool("dry-run")
		gatewayPort, _ := cmd.Flags().GetInt("gateway-port")

		switch runtime.GOOS {
		case "darwin":
			return hardenMacOSFirewall(dryRunFlag, gatewayPort)
		case "linux":
			return hardenLinuxFirewall(dryRunFlag, gatewayPort)
		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("moltbot-hardener %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		fmt.Printf("  os:     %s\n", runtime.GOOS)
		fmt.Printf("  arch:   %s\n", runtime.GOARCH)
	},
}

func init() {
	// Audit command flags
	auditCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show verbose output")
	auditCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results as JSON")
	auditCmd.Flags().StringSliceVar(&skipChecks, "skip", nil, "Check IDs to skip (comma-separated)")
	auditCmd.Flags().StringSliceVar(&onlyChecks, "only", nil, "Only run these check IDs (comma-separated)")

	// Apply command flags
	applyCmd.Flags().BoolVarP(&autoFix, "yes", "y", false, "Apply all fixes without confirmation")
	applyCmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Show what would be fixed without making changes")
	applyCmd.Flags().BoolVarP(&forceRun, "force", "f", false, "Force run even if moltbot is running")

	// Fix command flags
	fixCmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Show what would be fixed without making changes")

	// Check-deps command flags
	checkDepsCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results as JSON")

	// Firewall command flags
	firewallHardenCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	firewallHardenCmd.Flags().Int("gateway-port", 18789, "Moltbot gateway port to protect")

	firewallCmd.AddCommand(firewallStatusCmd)
	firewallCmd.AddCommand(firewallHardenCmd)

	// Add all commands
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(checkDepsCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(firewallCmd)
	rootCmd.AddCommand(versionCmd)
}

// Command implementations

func runAudit(cmd *cobra.Command, args []string) error {
	scanner := audit.NewScanner()
	scanner.SetVerbose(verbose)

	if len(skipChecks) > 0 {
		scanner.SetSkipChecks(skipChecks)
	}
	if len(onlyChecks) > 0 {
		scanner.SetOnlyChecks(onlyChecks)
	}

	fmt.Println(titleStyle.Render("Moltbot Security Audit"))
	fmt.Println()

	// Read configuration
	if err := scanner.ScanConfig(); err != nil {
		fmt.Println(warningStyle.Render("Warning: Could not read moltbot config: " + err.Error()))
	}

	cfg := scanner.GetConfig()
	fmt.Printf("%s %s\n", dimStyle.Render("Platform:"), boldStyle.Render(cfg.Platform))
	fmt.Printf("%s %s\n", dimStyle.Render("Config path:"), cfg.MoltbotConfigPath)
	fmt.Println()

	// Run scan
	result, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("error during scan: %w", err)
	}

	// Output results
	if jsonOutput {
		printJSONResult(result)
	} else {
		printFormattedResult(result)
	}

	// Exit with error code if critical/high findings
	if result.HasCritical() {
		os.Exit(2)
	}
	if result.HasHigh() {
		os.Exit(1)
	}

	return nil
}

func runApply(cmd *cobra.Command, args []string) error {
	// Check if bot is running and warn user
	if !warnIfBotRunning() {
		return nil // User chose to abort
	}

	scanner := audit.NewScanner()

	if err := scanner.ScanConfig(); err != nil {
		fmt.Println(warningStyle.Render("Warning: Could not read moltbot config"))
	}

	result, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("error during scan: %w", err)
	}

	fixable := 0
	for _, f := range result.Findings {
		if f.AutoFixable && !f.Fixed {
			fixable++
		}
	}

	if fixable == 0 {
		fmt.Println(successStyle.Render("No auto-fixable issues found."))
		return nil
	}

	fmt.Printf("Found %d auto-fixable issues.\n\n", fixable)

	if dryRun {
		fmt.Println(infoStyle.Render("Dry run mode - no changes will be made\n"))
	}

	for _, f := range result.Findings {
		if !f.AutoFixable || f.Fixed {
			continue
		}

		fmt.Printf("%s %s\n", getSeverityBadge(f.Severity), boldStyle.Render(f.Title))
		fmt.Printf("  %s\n", dimStyle.Render(f.Remediation))

		if !dryRun {
			if autoFix || confirmFix(f.CheckID) {
				if err := applyFixForFinding(&f); err != nil {
					fmt.Printf("  %s\n\n", errorStyle.Render("Failed: "+err.Error()))
				} else {
					fmt.Printf("  %s\n\n", successStyle.Render("Fixed!"))
				}
			} else {
				fmt.Printf("  %s\n\n", dimStyle.Render("Skipped"))
			}
		}
	}

	return nil
}

func runFix(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// Run in interactive mode if no check ID specified
		return runInteractiveTUI()
	}

	checkID := args[0]
	scanner := audit.NewScanner()

	if err := scanner.ScanConfig(); err != nil {
		fmt.Println(warningStyle.Render("Warning: Could not read moltbot config"))
	}

	result, err := scanner.ScanSingle(checkID)
	if err != nil {
		return err
	}

	if len(result.Findings) == 0 {
		fmt.Println(successStyle.Render("No issues found for check " + checkID))
		return nil
	}

	for _, f := range result.Findings {
		if !f.AutoFixable {
			fmt.Printf("%s is not auto-fixable.\n", checkID)
			fmt.Printf("Manual remediation: %s\n", f.Remediation)
			continue
		}

		if dryRun {
			fmt.Printf("Would fix: %s - %s\n", f.CheckID, f.Title)
			fmt.Printf("  %s\n", f.Remediation)
		} else {
			if err := applyFixForFinding(&f); err != nil {
				fmt.Println(errorStyle.Render("Failed to apply fix: " + err.Error()))
			} else {
				fmt.Println(successStyle.Render("Fixed: " + f.Title))
			}
		}
	}

	return nil
}

func runCheckDeps(cmd *cobra.Command, args []string) error {
	fmt.Println(titleStyle.Render("Dependency Security Check"))
	fmt.Println()

	scanner := audit.NewScanner()
	scanner.SetOnlyChecks([]string{"DEP-001", "DEP-002"})

	result, err := scanner.Scan()
	if err != nil {
		return err
	}

	if jsonOutput {
		printJSONResult(result)
	} else {
		if len(result.Findings) == 0 {
			fmt.Println(successStyle.Render("No dependency vulnerabilities found."))
		} else {
			printFormattedResult(result)
		}
	}

	return nil
}

func runList(cmd *cobra.Command, args []string) {
	scanner := audit.NewScanner()
	checks := scanner.ListChecks()

	fmt.Println(titleStyle.Render("Available Security Checks"))
	fmt.Println()

	categories := scanner.ListCategories()
	for _, cat := range categories {
		fmt.Printf("%s\n", boldStyle.Render(string(cat)))

		for _, check := range checks {
			if check.Category == cat {
				fixable := ""
				if check.AutoFixable {
					fixable = successStyle.Render(" [auto-fix]")
				}
				fmt.Printf("  %s %s%s\n", dimStyle.Render(check.ID), check.Title, fixable)
			}
		}
		fmt.Println()
	}
}

// Interactive TUI

func runInteractiveTUI() error {
	p := tea.NewProgram(initialModel())
	_, err := p.Run()
	return err
}

// TUI Model

type tuiState int

const (
	stateMenu tuiState = iota
	stateScanning
	stateResults
	stateFixing
)

type model struct {
	state      tuiState
	scanner    *audit.Scanner
	result     *audit.ScanResult
	list       list.Model
	spinner    spinner.Model
	err        error
	width      int
	height     int
	fixResults []string
}

type scanCompleteMsg struct {
	result *audit.ScanResult
	err    error
}

type menuItem struct {
	title string
	desc  string
}

func (i menuItem) Title() string       { return i.title }
func (i menuItem) Description() string { return i.desc }
func (i menuItem) FilterValue() string { return i.title }

func initialModel() model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED"))

	items := []list.Item{
		menuItem{title: "Full Audit", desc: "Run all security checks"},
		menuItem{title: "Credentials", desc: "Check credential security"},
		menuItem{title: "Network", desc: "Check network security"},
		menuItem{title: "Permissions", desc: "Check file permissions"},
		menuItem{title: "Docker", desc: "Check Docker sandbox security"},
		menuItem{title: "Auto-Fix All", desc: "Automatically fix all fixable issues"},
		menuItem{title: "Exit", desc: "Exit the program"},
	}

	delegate := list.NewDefaultDelegate()
	l := list.New(items, delegate, 0, 0)
	l.Title = "Moltbot Security Hardener"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	return model{
		state:   stateMenu,
		scanner: audit.NewScanner(),
		list:    l,
		spinner: s,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width-4, msg.Height-4)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "enter":
			if m.state == stateMenu {
				return m.handleMenuSelection()
			}
			if m.state == stateResults {
				m.state = stateMenu
				return m, nil
			}
		case "esc":
			if m.state != stateMenu {
				m.state = stateMenu
				return m, nil
			}
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case scanCompleteMsg:
		m.result = msg.result
		m.err = msg.err
		m.state = stateResults
		return m, nil
	}

	if m.state == stateMenu {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) handleMenuSelection() (tea.Model, tea.Cmd) {
	item, ok := m.list.SelectedItem().(menuItem)
	if !ok {
		return m, nil
	}

	switch item.title {
	case "Exit":
		return m, tea.Quit
	case "Full Audit":
		m.state = stateScanning
		m.scanner.SetSkipChecks(nil)
		m.scanner.SetOnlyChecks(nil)
		return m, m.runScan()
	case "Credentials":
		m.state = stateScanning
		m.scanner.SetOnlyChecks([]string{"CRED-001", "CRED-002", "CRED-003", "CRED-004", "CRED-005", "CRED-006"})
		return m, m.runScan()
	case "Network":
		m.state = stateScanning
		m.scanner.SetOnlyChecks([]string{"NET-001", "NET-002", "NET-003", "NET-004", "NET-005"})
		return m, m.runScan()
	case "Permissions":
		m.state = stateScanning
		m.scanner.SetOnlyChecks([]string{"PERM-001", "PERM-002", "PERM-003", "PERM-004"})
		return m, m.runScan()
	case "Docker":
		m.state = stateScanning
		m.scanner.SetOnlyChecks([]string{"DOCK-001", "DOCK-002", "DOCK-003"})
		return m, m.runScan()
	case "Auto-Fix All":
		m.state = stateFixing
		m.fixResults = nil
		return m, m.runAutoFix()
	}

	return m, nil
}

func (m model) runScan() tea.Cmd {
	return func() tea.Msg {
		_ = m.scanner.ScanConfig()
		result, err := m.scanner.Scan()
		return scanCompleteMsg{result: result, err: err}
	}
}

func (m model) runAutoFix() tea.Cmd {
	return func() tea.Msg {
		_ = m.scanner.ScanConfig()
		result, _ := m.scanner.Scan()

		for i := range result.Findings {
			f := &result.Findings[i]
			if f.AutoFixable && !f.Fixed {
				err := applyFixForFinding(f)
				if err == nil {
					f.Fixed = true
				}
			}
		}

		return scanCompleteMsg{result: result, err: nil}
	}
}

func (m model) View() string {
	switch m.state {
	case stateMenu:
		return m.list.View()

	case stateScanning:
		return fmt.Sprintf("\n\n   %s Scanning...\n\n   Press ESC to cancel", m.spinner.View())

	case stateResults:
		return m.renderResults()

	case stateFixing:
		var b strings.Builder
		b.WriteString("\n\n   " + titleStyle.Render("Auto-Fix Results") + "\n\n")
		for _, r := range m.fixResults {
			b.WriteString("   " + r + "\n")
		}
		b.WriteString("\n   Press ENTER or ESC to return to menu\n")
		return b.String()
	}

	return ""
}

func (m model) renderResults() string {
	if m.err != nil {
		return fmt.Sprintf("\n\n   %s\n\n   Press ENTER to return", errorStyle.Render("Error: "+m.err.Error()))
	}

	if m.result == nil {
		return "\n\n   No results available\n\n   Press ENTER to return"
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("   " + titleStyle.Render("Scan Results") + "\n\n")

	// Summary
	b.WriteString(fmt.Sprintf("   Total: %d  ", m.result.TotalChecks))
	b.WriteString(successStyle.Render(fmt.Sprintf("Passed: %d  ", m.result.PassedChecks)))
	b.WriteString(errorStyle.Render(fmt.Sprintf("Failed: %d  ", m.result.FailedChecks)))
	b.WriteString(dimStyle.Render(fmt.Sprintf("Skipped: %d", m.result.SkippedChecks)))
	b.WriteString("\n\n")

	// Findings
	if len(m.result.Findings) == 0 {
		b.WriteString("   " + successStyle.Render("No security issues found!") + "\n")
	} else {
		for _, f := range m.result.Findings {
			badge := getSeverityBadge(f.Severity)
			fixable := ""
			if f.AutoFixable {
				fixable = successStyle.Render(" [auto-fix]")
			}
			b.WriteString(fmt.Sprintf("   %s %s%s\n", badge, f.Title, fixable))
			b.WriteString(fmt.Sprintf("      %s\n", dimStyle.Render(f.Remediation)))
		}
	}

	b.WriteString("\n   Press ENTER or ESC to return to menu\n")
	return b.String()
}

// Helper functions

func getSeverityBadge(s audit.Severity) string {
	switch s {
	case audit.SeverityCritical:
		return criticalStyle.Render("CRITICAL")
	case audit.SeverityHigh:
		return highStyle.Render("HIGH")
	case audit.SeverityMedium:
		return mediumStyle.Render("MEDIUM")
	case audit.SeverityLow:
		return lowStyle.Render("LOW")
	case audit.SeverityInfo:
		return infoSeverityStyle.Render("INFO")
	default:
		return dimStyle.Render("UNKNOWN")
	}
}

func printFormattedResult(result *audit.ScanResult) {
	summary := result.Summary()
	fmt.Printf("Checks: %d total, %s passed, %s failed, %d skipped\n\n",
		result.TotalChecks,
		successStyle.Render(fmt.Sprintf("%d", result.PassedChecks)),
		errorStyle.Render(fmt.Sprintf("%d", result.FailedChecks)),
		result.SkippedChecks,
	)

	if len(result.Findings) == 0 {
		fmt.Println(successStyle.Render("No security issues found!"))
		return
	}

	fmt.Printf("Findings: %s critical, %s high, %s medium, %s low\n\n",
		criticalStyle.Render(fmt.Sprintf("%d", summary[audit.SeverityCritical])),
		highStyle.Render(fmt.Sprintf("%d", summary[audit.SeverityHigh])),
		mediumStyle.Render(fmt.Sprintf("%d", summary[audit.SeverityMedium])),
		lowStyle.Render(fmt.Sprintf("%d", summary[audit.SeverityLow])),
	)

	for _, f := range result.Findings {
		badge := getSeverityBadge(f.Severity)
		fixable := ""
		if f.AutoFixable {
			fixable = successStyle.Render(" [auto-fix]")
		}

		fmt.Printf("%s %s %s%s\n", badge, dimStyle.Render(f.CheckID), boldStyle.Render(f.Title), fixable)

		if f.File != "" {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Printf("   %s %s\n", dimStyle.Render("Location:"), loc)
		}

		if f.Evidence != "" {
			fmt.Printf("   %s %s\n", dimStyle.Render("Evidence:"), f.Evidence)
		}

		fmt.Printf("   %s %s\n\n", dimStyle.Render("Fix:"), f.Remediation)
	}

	if fixable := result.FixableCount(); fixable > 0 {
		fmt.Printf("\n%s issues can be automatically fixed. Run: hardener apply\n",
			successStyle.Render(fmt.Sprintf("%d", fixable)))
	}
}

func printJSONResult(result *audit.ScanResult) {
	fmt.Println("{")
	fmt.Printf("  \"total_checks\": %d,\n", result.TotalChecks)
	fmt.Printf("  \"passed_checks\": %d,\n", result.PassedChecks)
	fmt.Printf("  \"failed_checks\": %d,\n", result.FailedChecks)
	fmt.Printf("  \"skipped_checks\": %d,\n", result.SkippedChecks)
	fmt.Printf("  \"platform\": \"%s\",\n", result.Platform)
	fmt.Println("  \"findings\": [")

	for i, f := range result.Findings {
		fmt.Println("    {")
		fmt.Printf("      \"check_id\": \"%s\",\n", f.CheckID)
		fmt.Printf("      \"severity\": \"%s\",\n", f.Severity.String())
		fmt.Printf("      \"title\": \"%s\",\n", f.Title)
		fmt.Printf("      \"category\": \"%s\",\n", f.Category)
		if f.File != "" {
			fmt.Printf("      \"file\": \"%s\",\n", f.File)
		}
		if f.Line > 0 {
			fmt.Printf("      \"line\": %d,\n", f.Line)
		}
		fmt.Printf("      \"remediation\": \"%s\",\n", f.Remediation)
		fmt.Printf("      \"auto_fixable\": %t,\n", f.AutoFixable)
		fmt.Printf("      \"fixed\": %t\n", f.Fixed)

		if i < len(result.Findings)-1 {
			fmt.Println("    },")
		} else {
			fmt.Println("    }")
		}
	}

	fmt.Println("  ]")
	fmt.Println("}")
}

func confirmFix(checkID string) bool {
	var response string
	fmt.Printf("Apply fix for %s? [y/N] ", checkID)
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

func applyFixForFinding(f *audit.AuditFinding) error {
	switch f.CheckID {
	case "CRED-002", "CRED-003":
		if f.File != "" {
			return os.Chmod(f.File, 0600)
		}
	case "CRED-006":
		if f.File != "" {
			return os.Remove(f.File)
		}
	case "PERM-001":
		if f.File != "" {
			return os.Chmod(f.File, 0700)
		}
	case "PERM-004":
		if f.File != "" {
			info, err := os.Stat(f.File)
			if err != nil {
				return err
			}
			return os.Chmod(f.File, info.Mode()&^0111)
		}
	case "NET-001", "CONF-001", "CONF-002":
		return fmt.Errorf("manual fix required: %s", f.Remediation)
	}

	return fmt.Errorf("no automatic fix available")
}

// Firewall functions

func checkMacOSFirewallStatus() error {
	fmt.Println("macOS Firewall Status")
	fmt.Println("=====================")

	pf := firewall.NewPFManager(false)
	if pf.IsAvailable() {
		enabled, err := pf.IsEnabled()
		if err != nil {
			fmt.Printf("PF (Packet Filter): Error - %v\n", err)
		} else if enabled {
			fmt.Println("PF (Packet Filter): Enabled")
		} else {
			fmt.Println("PF (Packet Filter): Disabled")
		}
	} else {
		fmt.Println("PF (Packet Filter): Not available")
	}

	appFw := firewall.NewAppFirewall(false)
	if appFw.IsAvailable() {
		enabled, err := appFw.IsEnabled()
		if err != nil {
			fmt.Printf("Application Firewall: Error - %v\n", err)
		} else if enabled {
			fmt.Println("Application Firewall: Enabled")
		} else {
			fmt.Println("Application Firewall: Disabled")
		}

		stealth, err := appFw.IsStealthModeEnabled()
		if err == nil {
			if stealth {
				fmt.Println("Stealth Mode: Enabled")
			} else {
				fmt.Println("Stealth Mode: Disabled")
			}
		}
	} else {
		fmt.Println("Application Firewall: Not available")
	}

	return nil
}

func checkLinuxFirewallStatus() error {
	fmt.Println("Linux Firewall Status")
	fmt.Println("=====================")

	ipt := firewall.NewIPTablesManager(false)
	if !ipt.IsAvailable() {
		fmt.Println("iptables: Not available")
		return nil
	}

	rules, err := ipt.ListRules()
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}

	fmt.Printf("iptables: Available (%d rules)\n", len(rules))

	hasMoltbotRules := false
	for _, rule := range rules {
		if rule.Comment != "" && len(rule.Comment) >= 7 && rule.Comment[:7] == "moltbot" {
			hasMoltbotRules = true
			break
		}
	}

	if hasMoltbotRules {
		fmt.Println("Moltbot rules: Present")
	} else {
		fmt.Println("Moltbot rules: Not configured")
	}

	return nil
}

func hardenMacOSFirewall(dryRunFlag bool, gatewayPort int) error {
	fmt.Println("Hardening macOS Firewall")
	fmt.Println("========================")

	if dryRunFlag {
		fmt.Println("[DRY RUN MODE - no changes will be made]")
		fmt.Println()
	}

	appFw := firewall.NewAppFirewall(dryRunFlag)
	if appFw.IsAvailable() {
		fmt.Println("Enabling application firewall...")
		if err := appFw.Enable(); err != nil {
			return err
		}

		fmt.Println("Enabling stealth mode...")
		if err := appFw.EnableStealthMode(); err != nil {
			return err
		}

		fmt.Println("Allowing signed apps...")
		if err := appFw.AllowSignedApps(); err != nil {
			return err
		}
	}

	pf := firewall.NewPFManager(dryRunFlag)
	if pf.IsAvailable() {
		fmt.Println("Enabling PF...")
		if err := pf.Enable(); err != nil {
			fmt.Printf("Warning: Could not enable PF: %v\n", err)
		}

		fmt.Printf("Restricting gateway port %d to localhost...\n", gatewayPort)
		if err := pf.RestrictGatewayPort(gatewayPort); err != nil {
			fmt.Printf("Warning: Could not restrict gateway port: %v\n", err)
		}

		fmt.Println("Blocking dangerous outbound ports...")
		if err := pf.BlockDangerousOutbound(); err != nil {
			fmt.Printf("Warning: Could not block dangerous ports: %v\n", err)
		}
	}

	fmt.Println()
	fmt.Println("Firewall hardening complete!")
	return nil
}

func hardenLinuxFirewall(dryRunFlag bool, gatewayPort int) error {
	fmt.Println("Hardening Linux Firewall")
	fmt.Println("========================")

	if dryRunFlag {
		fmt.Println("[DRY RUN MODE - no changes will be made]")
		fmt.Println()
	}

	ipt := firewall.NewIPTablesManager(dryRunFlag)
	if !ipt.IsAvailable() {
		return fmt.Errorf("iptables is not available")
	}

	fmt.Println("Creating Moltbot firewall chain...")
	if err := ipt.CreateMoltbotChain(); err != nil {
		return err
	}

	fmt.Printf("Restricting gateway port %d to localhost...\n", gatewayPort)
	if err := ipt.RestrictGatewayPort(gatewayPort); err != nil {
		return err
	}

	fmt.Println("Blocking dangerous outbound ports...")
	if err := ipt.BlockDangerousOutbound(); err != nil {
		return err
	}

	fmt.Println("Saving firewall rules...")
	if err := ipt.SaveRules(); err != nil {
		fmt.Printf("Warning: Could not persist rules: %v\n", err)
	}

	fmt.Println()
	fmt.Println("Firewall hardening complete!")
	return nil
}
