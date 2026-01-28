package ui

import (
	"github.com/charmbracelet/lipgloss"
)

// Color palette for the TUI.
var (
	// Primary colors
	ColorPrimary   = lipgloss.Color("#7C3AED") // Purple
	ColorSecondary = lipgloss.Color("#06B6D4") // Cyan
	ColorAccent    = lipgloss.Color("#F59E0B") // Amber

	// Severity colors
	ColorCritical = lipgloss.Color("#EF4444") // Red
	ColorHigh     = lipgloss.Color("#F97316") // Orange
	ColorMedium   = lipgloss.Color("#EAB308") // Yellow
	ColorLow      = lipgloss.Color("#3B82F6") // Blue

	// Status colors
	ColorSuccess = lipgloss.Color("#10B981") // Green
	ColorWarning = lipgloss.Color("#F59E0B") // Amber
	ColorError   = lipgloss.Color("#EF4444") // Red
	ColorInfo    = lipgloss.Color("#6366F1") // Indigo

	// Neutral colors
	ColorMuted      = lipgloss.Color("#6B7280") // Gray
	ColorBorder     = lipgloss.Color("#374151") // Dark gray
	ColorBackground = lipgloss.Color("#1F2937") // Darker gray
	ColorForeground = lipgloss.Color("#F9FAFB") // White-ish
)

// Styles contains all lipgloss styles for the TUI.
type Styles struct {
	// App container
	App lipgloss.Style

	// Title and headers
	Title       lipgloss.Style
	Subtitle    lipgloss.Style
	SectionHead lipgloss.Style

	// Content areas
	Box           lipgloss.Style
	BoxFocused    lipgloss.Style
	StatusBar     lipgloss.Style
	HelpBar       lipgloss.Style
	ContentArea   lipgloss.Style

	// Text styles
	Text        lipgloss.Style
	TextMuted   lipgloss.Style
	TextBold    lipgloss.Style
	TextError   lipgloss.Style
	TextSuccess lipgloss.Style
	TextWarning lipgloss.Style

	// List items
	ListItem         lipgloss.Style
	ListItemSelected lipgloss.Style
	ListItemChecked  lipgloss.Style

	// Severity badges
	BadgeCritical lipgloss.Style
	BadgeHigh     lipgloss.Style
	BadgeMedium   lipgloss.Style
	BadgeLow      lipgloss.Style

	// Status badges
	BadgeSuccess lipgloss.Style
	BadgeWarning lipgloss.Style
	BadgeError   lipgloss.Style
	BadgeInfo    lipgloss.Style
	BadgePending lipgloss.Style

	// Progress bar
	ProgressFilled lipgloss.Style
	ProgressEmpty  lipgloss.Style

	// Buttons
	Button        lipgloss.Style
	ButtonFocused lipgloss.Style

	// Logo/ASCII art
	Logo lipgloss.Style
}

// DefaultStyles returns the default style configuration.
func DefaultStyles() Styles {
	s := Styles{}

	// App container
	s.App = lipgloss.NewStyle().
		Padding(1, 2)

	// Title and headers
	s.Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginBottom(1)

	s.Subtitle = lipgloss.NewStyle().
		Foreground(ColorSecondary).
		MarginBottom(1)

	s.SectionHead = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorForeground).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(ColorBorder).
		MarginTop(1).
		MarginBottom(1)

	// Content areas
	s.Box = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Padding(1, 2)

	s.BoxFocused = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Padding(1, 2)

	s.StatusBar = lipgloss.NewStyle().
		Background(ColorBackground).
		Foreground(ColorForeground).
		Padding(0, 1).
		MarginTop(1)

	s.HelpBar = lipgloss.NewStyle().
		Foreground(ColorMuted).
		MarginTop(1)

	s.ContentArea = lipgloss.NewStyle().
		Padding(1, 0)

	// Text styles
	s.Text = lipgloss.NewStyle().
		Foreground(ColorForeground)

	s.TextMuted = lipgloss.NewStyle().
		Foreground(ColorMuted)

	s.TextBold = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorForeground)

	s.TextError = lipgloss.NewStyle().
		Foreground(ColorError)

	s.TextSuccess = lipgloss.NewStyle().
		Foreground(ColorSuccess)

	s.TextWarning = lipgloss.NewStyle().
		Foreground(ColorWarning)

	// List items
	s.ListItem = lipgloss.NewStyle().
		PaddingLeft(2)

	s.ListItemSelected = lipgloss.NewStyle().
		PaddingLeft(2).
		Background(ColorBackground).
		Foreground(ColorPrimary).
		Bold(true)

	s.ListItemChecked = lipgloss.NewStyle().
		PaddingLeft(2).
		Foreground(ColorSuccess)

	// Severity badges
	s.BadgeCritical = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorCritical).
		Foreground(lipgloss.Color("#FFFFFF"))

	s.BadgeHigh = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorHigh).
		Foreground(lipgloss.Color("#FFFFFF"))

	s.BadgeMedium = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorMedium).
		Foreground(lipgloss.Color("#000000"))

	s.BadgeLow = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorLow).
		Foreground(lipgloss.Color("#FFFFFF"))

	// Status badges
	s.BadgeSuccess = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorSuccess).
		Foreground(lipgloss.Color("#FFFFFF"))

	s.BadgeWarning = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorWarning).
		Foreground(lipgloss.Color("#000000"))

	s.BadgeError = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorError).
		Foreground(lipgloss.Color("#FFFFFF"))

	s.BadgeInfo = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorInfo).
		Foreground(lipgloss.Color("#FFFFFF"))

	s.BadgePending = lipgloss.NewStyle().
		Padding(0, 1).
		Bold(true).
		Background(ColorMuted).
		Foreground(lipgloss.Color("#FFFFFF"))

	// Progress bar
	s.ProgressFilled = lipgloss.NewStyle().
		Background(ColorPrimary)

	s.ProgressEmpty = lipgloss.NewStyle().
		Background(ColorBorder)

	// Buttons
	s.Button = lipgloss.NewStyle().
		Padding(0, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder)

	s.ButtonFocused = lipgloss.NewStyle().
		Padding(0, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Bold(true)

	// Logo
	s.Logo = lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Bold(true)

	return s
}

// SeverityStyle returns the appropriate badge style for a severity level.
func (s Styles) SeverityStyle(severity Severity) lipgloss.Style {
	switch severity {
	case SeverityCritical:
		return s.BadgeCritical
	case SeverityHigh:
		return s.BadgeHigh
	case SeverityMedium:
		return s.BadgeMedium
	case SeverityLow:
		return s.BadgeLow
	default:
		return s.BadgeInfo
	}
}

// SeverityColor returns the color for a severity level.
func SeverityColor(severity Severity) lipgloss.Color {
	switch severity {
	case SeverityCritical:
		return ColorCritical
	case SeverityHigh:
		return ColorHigh
	case SeverityMedium:
		return ColorMedium
	case SeverityLow:
		return ColorLow
	default:
		return ColorMuted
	}
}
