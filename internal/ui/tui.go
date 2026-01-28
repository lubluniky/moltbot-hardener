package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// AppState represents the current state of the TUI.
type AppState int

const (
	StateWelcome AppState = iota
	StateDependencyCheck
	StateScanning
	StateResults
	StateFixing
	StateComplete
)

// getLogo returns the ASCII logo for the welcome screen.
func getLogo() string {
	lines := []string{
		" __  __       _ _   _           _",
		"|  \\/  | ___ | | |_| |__   ___ | |_",
		"| |\\/| |/ _ \\| | __| '_ \\ / _ \\| __|",
		"| |  | | (_) | | |_| |_) | (_) | |_",
		"|_|  |_|\\___/|_|\\__|_.__/ \\___/ \\__|",
		"     _   _               _",
		"    | | | | __ _ _ __ __| | ___ _ __   ___ _ __",
		"    | |_| |/ _` | '__/ _` |/ _ \\ '_ \\ / _ \\ '__|",
		"    |  _  | (_| | | | (_| |  __/ | | |  __/ |",
		"    |_| |_|\\__,_|_|  \\__,_|\\___|_| |_|\\___|_|",
	}
	return strings.Join(lines, "\n")
}

// Key bindings
type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Enter  key.Binding
	Space  key.Binding
	Tab    key.Binding
	Fix    key.Binding
	FixAll key.Binding
	Quit   key.Binding
	Help   key.Binding
	Back   key.Binding
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("up/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("down/j", "down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
	Space: key.NewBinding(
		key.WithKeys(" "),
		key.WithHelp("space", "toggle"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next section"),
	),
	Fix: key.NewBinding(
		key.WithKeys("f"),
		key.WithHelp("f", "fix selected"),
	),
	FixAll: key.NewBinding(
		key.WithKeys("F"),
		key.WithHelp("F", "fix all"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	),
}

// Model is the main TUI model.
type Model struct {
	// State
	state     AppState
	prevState AppState

	// Window dimensions
	width  int
	height int

	// Styles
	styles Styles

	// Components
	vulnList    VulnerabilityList
	progressBar ProgressBar
	depList     DependencyList
	spinner     Spinner
	helpView    HelpView

	// Data
	dependencies    []DependencyCheck
	vulnerabilities []Vulnerability
	scanResult      *ScanResult

	// Progress tracking
	scanProgress int
	scanTotal    int
	scanMessage  string
	fixProgress  int
	fixTotal     int
	fixMessage   string

	// Flags
	showHelp       bool
	autoFixEnabled bool
	selectedToFix  map[string]bool

	// Animation
	tickCount int

	// Error handling
	lastError error
}

// NewModel creates a new TUI model.
func NewModel() Model {
	styles := DefaultStyles()
	return Model{
		state:         StateWelcome,
		styles:        styles,
		vulnList:      NewVulnerabilityList(styles),
		progressBar:   NewProgressBar(styles),
		depList:       NewDependencyList(styles),
		spinner:       NewSpinner(styles),
		helpView:      NewHelpView(styles),
		selectedToFix: make(map[string]bool),
	}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		tickCmd(),
	)
}

// tickCmd returns a command that sends tick messages.
func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles messages and updates the model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.vulnList.Width = msg.Width - 10
		m.vulnList.Height = msg.Height - 15
		return m, nil

	case tea.KeyMsg:
		return m.handleKeyPress(msg)

	case TickMsg:
		m.tickCount++
		m.spinner.Tick()
		return m, tickCmd()

	case DependencyCheckMsg:
		m.dependencies = append(m.dependencies, msg.Check)
		m.depList.SetChecks(m.dependencies)
		return m, nil

	case DependencyCheckCompleteMsg:
		if msg.AllFound {
			m.state = StateScanning
		}
		return m, nil

	case ScanProgressMsg:
		m.scanProgress = msg.Current
		m.scanTotal = msg.Total
		m.scanMessage = msg.Message
		m.progressBar.SetProgress(msg.Current, msg.Total)
		m.progressBar.Label = msg.Message
		return m, nil

	case ScanCompleteMsg:
		m.state = StateResults
		m.scanResult = &msg.Result
		m.vulnerabilities = msg.Result.Vulnerabilities
		m.vulnList.SetItems(m.vulnerabilities)
		return m, nil

	case FixProgressMsg:
		m.fixMessage = msg.Status
		// Update the vulnerability status
		for i := range m.vulnerabilities {
			if m.vulnerabilities[i].ID == msg.VulnerabilityID {
				m.vulnerabilities[i].Fixing = true
				break
			}
		}
		m.vulnList.SetItems(m.vulnerabilities)
		return m, nil

	case FixCompleteMsg:
		// Update the vulnerability status
		for i := range m.vulnerabilities {
			if m.vulnerabilities[i].ID == msg.Result.VulnerabilityID {
				m.vulnerabilities[i].Fixing = false
				m.vulnerabilities[i].Fixed = msg.Result.Success
				break
			}
		}
		m.vulnList.SetItems(m.vulnerabilities)
		m.fixProgress++
		return m, nil

	case AllFixesCompleteMsg:
		m.state = StateComplete
		return m, nil

	case ErrorMsg:
		m.lastError = msg.Error
		return m, nil

	case NavigateMsg:
		m.prevState = m.state
		m.state = msg.State
		return m, nil

	case QuitMsg:
		return m, tea.Quit
	}

	return m, nil
}

func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, keys.Help):
		m.showHelp = !m.showHelp
		return m, nil

	case key.Matches(msg, keys.Back):
		if m.showHelp {
			m.showHelp = false
		} else if m.state == StateResults {
			m.state = StateWelcome
		}
		return m, nil
	}

	// State-specific key handling
	switch m.state {
	case StateWelcome:
		if key.Matches(msg, keys.Enter) || key.Matches(msg, keys.Space) {
			m.state = StateDependencyCheck
			return m, nil
		}

	case StateResults:
		switch {
		case key.Matches(msg, keys.Up):
			m.vulnList.MoveUp()
		case key.Matches(msg, keys.Down):
			m.vulnList.MoveDown()
		case key.Matches(msg, keys.Space):
			// Toggle selection for fix
			if selected := m.vulnList.Selected(); selected != nil && selected.CanAutoFix {
				if m.selectedToFix[selected.ID] {
					delete(m.selectedToFix, selected.ID)
				} else {
					m.selectedToFix[selected.ID] = true
				}
			}
		case key.Matches(msg, keys.Fix):
			// Fix selected vulnerability
			if selected := m.vulnList.Selected(); selected != nil && selected.CanAutoFix {
				m.state = StateFixing
				m.fixTotal = 1
				m.fixProgress = 0
				return m, nil
			}
		case key.Matches(msg, keys.FixAll):
			// Fix all auto-fixable vulnerabilities
			fixableCount := 0
			for _, v := range m.vulnerabilities {
				if v.CanAutoFix && !v.Fixed {
					fixableCount++
				}
			}
			if fixableCount > 0 {
				m.state = StateFixing
				m.fixTotal = fixableCount
				m.fixProgress = 0
				return m, nil
			}
		}
	}

	return m, nil
}

// View renders the TUI.
func (m Model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	if m.showHelp {
		return m.renderHelpScreen()
	}

	switch m.state {
	case StateWelcome:
		return m.renderWelcome()
	case StateDependencyCheck:
		return m.renderDependencyCheck()
	case StateScanning:
		return m.renderScanning()
	case StateResults:
		return m.renderResults()
	case StateFixing:
		return m.renderFixing()
	case StateComplete:
		return m.renderComplete()
	default:
		return "Unknown state"
	}
}

func (m Model) renderWelcome() string {
	var b strings.Builder

	// Logo
	logoStyled := m.styles.Logo.Render(getLogo())
	b.WriteString(logoStyled)
	b.WriteString("\n\n")

	// Welcome message
	welcome := m.styles.Title.Render("Security Hardening Tool for Moltbot")
	b.WriteString(welcome)
	b.WriteString("\n\n")

	subtitle := m.styles.Subtitle.Render("Scan, detect, and fix security vulnerabilities in your Moltbot installation")
	b.WriteString(subtitle)
	b.WriteString("\n\n")

	// Features list
	features := []string{
		"Check firewall configuration",
		"Scan for exposed credentials",
		"Verify gateway security settings",
		"Audit Docker container isolation",
		"Review pairing code security",
	}

	for _, f := range features {
		b.WriteString(fmt.Sprintf("  %s %s\n",
			m.styles.TextSuccess.Render("*"),
			m.styles.Text.Render(f),
		))
	}
	b.WriteString("\n")

	// Start prompt
	startPrompt := m.styles.Box.Render(
		m.styles.TextBold.Render("Press ENTER or SPACE to start scanning"),
	)
	b.WriteString(startPrompt)
	b.WriteString("\n\n")

	// Help hint
	helpHint := m.styles.TextMuted.Render("Press ? for help  |  q to quit")
	b.WriteString(helpHint)

	return m.styles.App.Render(b.String())
}

func (m Model) renderDependencyCheck() string {
	var b strings.Builder

	title := m.styles.Title.Render("Checking Dependencies")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Spinner
	m.spinner.Label = "Checking required tools..."
	b.WriteString(m.spinner.View())
	b.WriteString("\n\n")

	// Dependency list
	b.WriteString(m.depList.View())
	b.WriteString("\n")

	return m.styles.App.Render(b.String())
}

func (m Model) renderScanning() string {
	var b strings.Builder

	title := m.styles.Title.Render("Scanning for Vulnerabilities")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Spinner with current task
	m.spinner.Label = m.scanMessage
	if m.spinner.Label == "" {
		m.spinner.Label = "Initializing scan..."
	}
	b.WriteString(m.spinner.View())
	b.WriteString("\n\n")

	// Progress bar
	b.WriteString(m.progressBar.View())
	b.WriteString("\n\n")

	// Scanning categories
	categories := []string{
		"Firewall rules",
		"Credential storage",
		"Gateway configuration",
		"Docker containers",
		"Network exposure",
		"File permissions",
	}

	scanIdx := m.scanProgress % len(categories)
	for i, cat := range categories {
		var icon string
		if i < scanIdx {
			icon = m.styles.TextSuccess.Render("[x]")
		} else if i == scanIdx {
			icon = lipgloss.NewStyle().Foreground(ColorPrimary).Render(">")
		} else {
			icon = m.styles.TextMuted.Render("[ ]")
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", icon, m.styles.Text.Render(cat)))
	}

	return m.styles.App.Render(b.String())
}

func (m Model) renderResults() string {
	var b strings.Builder

	title := m.styles.Title.Render("Scan Results")
	b.WriteString(title)
	b.WriteString("\n")

	// Summary line
	if m.scanResult != nil {
		critCount := 0
		highCount := 0
		medCount := 0
		lowCount := 0
		for _, v := range m.vulnerabilities {
			if v.Fixed {
				continue
			}
			switch v.Severity {
			case SeverityCritical:
				critCount++
			case SeverityHigh:
				highCount++
			case SeverityMedium:
				medCount++
			case SeverityLow:
				lowCount++
			}
		}

		summary := fmt.Sprintf("Found: %s %d  %s %d  %s %d  %s %d",
			m.styles.BadgeCritical.Render("CRIT"), critCount,
			m.styles.BadgeHigh.Render("HIGH"), highCount,
			m.styles.BadgeMedium.Render("MED"), medCount,
			m.styles.BadgeLow.Render("LOW"), lowCount,
		)
		b.WriteString(m.styles.TextMuted.Render(summary))
		b.WriteString("\n\n")
	}

	// Vulnerability list
	listBox := m.styles.Box.Width(m.width - 6).Render(m.vulnList.View())
	b.WriteString(listBox)
	b.WriteString("\n\n")

	// Selected vulnerability details
	if selected := m.vulnList.Selected(); selected != nil {
		detailTitle := m.styles.SectionHead.Render("Details")
		b.WriteString(detailTitle)
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", m.styles.Text.Render(selected.Description)))
		b.WriteString(fmt.Sprintf("  %s %s\n",
			m.styles.TextMuted.Render("Category:"),
			m.styles.Text.Render(selected.Category),
		))
		if selected.CanAutoFix {
			b.WriteString(fmt.Sprintf("  %s\n", m.styles.TextSuccess.Render("Auto-fix available")))
		}
		b.WriteString("\n")
	}

	// Help bar
	m.helpView.SetBindings([]KeyBinding{
		{Key: "up/down", Description: "navigate"},
		{Key: "f", Description: "fix selected"},
		{Key: "F", Description: "fix all"},
		{Key: "q", Description: "quit"},
	})
	b.WriteString(m.helpView.View())

	return m.styles.App.Render(b.String())
}

func (m Model) renderFixing() string {
	var b strings.Builder

	title := m.styles.Title.Render("Applying Fixes")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Spinner
	m.spinner.Label = m.fixMessage
	if m.spinner.Label == "" {
		m.spinner.Label = "Preparing fixes..."
	}
	b.WriteString(m.spinner.View())
	b.WriteString("\n\n")

	// Progress
	m.progressBar.SetProgress(m.fixProgress, m.fixTotal)
	m.progressBar.Label = fmt.Sprintf("Fixing vulnerabilities (%d/%d)", m.fixProgress, m.fixTotal)
	b.WriteString(m.progressBar.View())
	b.WriteString("\n\n")

	// List of vulnerabilities being fixed
	b.WriteString(m.vulnList.View())
	b.WriteString("\n")

	return m.styles.App.Render(b.String())
}

func (m Model) renderComplete() string {
	var b strings.Builder

	// Check if all vulnerabilities are fixed
	allFixed := true
	fixedCount := 0
	totalCount := len(m.vulnerabilities)
	for _, v := range m.vulnerabilities {
		if v.Fixed {
			fixedCount++
		} else {
			allFixed = false
		}
	}

	if allFixed && totalCount > 0 {
		// All secure!
		secureArt := getSecureArt()
		b.WriteString(m.styles.TextSuccess.Render(secureArt))
		b.WriteString("\n")
		title := m.styles.Title.Render("Security Hardening Complete!")
		b.WriteString(title)
	} else if totalCount == 0 {
		// No vulnerabilities found
		cleanArt := getCleanArt()
		b.WriteString(m.styles.TextSuccess.Render(cleanArt))
		b.WriteString("\n")
		title := m.styles.Title.Render("Your Moltbot installation is secure!")
		b.WriteString(title)
	} else {
		// Some issues remain
		warningArt := getWarningArt()
		b.WriteString(m.styles.TextWarning.Render(warningArt))
		b.WriteString("\n")
		title := m.styles.Title.Render("Security Hardening Incomplete")
		b.WriteString(title)
	}
	b.WriteString("\n\n")

	// Summary stats
	summary := m.styles.Box.Render(
		fmt.Sprintf(
			"%s\n  %s %d\n  %s %d\n  %s %d",
			m.styles.SectionHead.Render("Summary"),
			m.styles.TextMuted.Render("Total issues found:"),
			totalCount,
			m.styles.TextSuccess.Render("Fixed:"),
			fixedCount,
			m.styles.TextWarning.Render("Remaining:"),
			totalCount-fixedCount,
		),
	)
	b.WriteString(summary)
	b.WriteString("\n\n")

	// Remaining issues
	if !allFixed && totalCount > 0 {
		b.WriteString(m.styles.SectionHead.Render("Remaining Issues"))
		b.WriteString("\n")
		for _, v := range m.vulnerabilities {
			if !v.Fixed {
				severity := m.styles.SeverityStyle(v.Severity).Render(v.Severity.String())
				b.WriteString(fmt.Sprintf("  %s %s\n", severity, v.Title))
			}
		}
		b.WriteString("\n")
	}

	// Exit hint
	b.WriteString(m.styles.TextMuted.Render("Press q to exit"))

	return m.styles.App.Render(b.String())
}

// getSecureArt returns ASCII art for the secure state.
func getSecureArt() string {
	return `
  +===================================+
  |                                   |
  |       [x] ALL SECURE              |
  |                                   |
  +===================================+
`
}

// getCleanArt returns ASCII art for the clean state.
func getCleanArt() string {
	return `
  +===================================+
  |                                   |
  |       [x] NO ISSUES FOUND         |
  |                                   |
  +===================================+
`
}

// getWarningArt returns ASCII art for the warning state.
func getWarningArt() string {
	return `
  +===================================+
  |                                   |
  |       [!] WARNINGS REMAIN         |
  |                                   |
  +===================================+
`
}

func (m Model) renderHelpScreen() string {
	var b strings.Builder

	title := m.styles.Title.Render("Help")
	b.WriteString(title)
	b.WriteString("\n\n")

	sections := []struct {
		title    string
		bindings []KeyBinding
	}{
		{
			title: "Navigation",
			bindings: []KeyBinding{
				{Key: "up/k", Description: "Move up"},
				{Key: "down/j", Description: "Move down"},
				{Key: "Enter", Description: "Select/Confirm"},
				{Key: "Space", Description: "Toggle selection"},
				{Key: "Esc", Description: "Go back"},
			},
		},
		{
			title: "Actions",
			bindings: []KeyBinding{
				{Key: "f", Description: "Fix selected vulnerability"},
				{Key: "F", Description: "Fix all auto-fixable vulnerabilities"},
			},
		},
		{
			title: "General",
			bindings: []KeyBinding{
				{Key: "?", Description: "Toggle help"},
				{Key: "q", Description: "Quit"},
				{Key: "Ctrl+C", Description: "Force quit"},
			},
		},
	}

	for _, section := range sections {
		b.WriteString(m.styles.SectionHead.Render(section.title))
		b.WriteString("\n")
		for _, binding := range section.bindings {
			keyStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorSecondary).
				Width(10).
				Render(binding.Key)
			b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle, binding.Description))
		}
		b.WriteString("\n")
	}

	b.WriteString(m.styles.TextMuted.Render("Press ? or Esc to close help"))

	return m.styles.App.Render(b.String())
}

// SetState changes the application state (for external control).
func (m *Model) SetState(state AppState) {
	m.prevState = m.state
	m.state = state
}

// GetState returns the current application state.
func (m Model) GetState() AppState {
	return m.state
}

// AddVulnerability adds a vulnerability to the list.
func (m *Model) AddVulnerability(v Vulnerability) {
	m.vulnerabilities = append(m.vulnerabilities, v)
	m.vulnList.SetItems(m.vulnerabilities)
}

// SetVulnerabilities sets the full vulnerability list.
func (m *Model) SetVulnerabilities(vulns []Vulnerability) {
	m.vulnerabilities = vulns
	m.vulnList.SetItems(vulns)
}

// Run starts the TUI application.
func Run() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
