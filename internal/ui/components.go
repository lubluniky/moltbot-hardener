package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// VulnerabilityList renders a list of vulnerabilities with selection support.
type VulnerabilityList struct {
	Items         []Vulnerability
	SelectedIndex int
	Width         int
	Height        int
	styles        Styles
}

// NewVulnerabilityList creates a new vulnerability list component.
func NewVulnerabilityList(styles Styles) VulnerabilityList {
	return VulnerabilityList{
		Items:         []Vulnerability{},
		SelectedIndex: 0,
		Width:         60,
		Height:        10,
		styles:        styles,
	}
}

// SetItems updates the list items.
func (v *VulnerabilityList) SetItems(items []Vulnerability) {
	v.Items = items
	if v.SelectedIndex >= len(items) {
		v.SelectedIndex = max(0, len(items)-1)
	}
}

// MoveUp moves selection up.
func (v *VulnerabilityList) MoveUp() {
	if v.SelectedIndex > 0 {
		v.SelectedIndex--
	}
}

// MoveDown moves selection down.
func (v *VulnerabilityList) MoveDown() {
	if v.SelectedIndex < len(v.Items)-1 {
		v.SelectedIndex++
	}
}

// Selected returns the currently selected vulnerability.
func (v *VulnerabilityList) Selected() *Vulnerability {
	if len(v.Items) == 0 || v.SelectedIndex >= len(v.Items) {
		return nil
	}
	return &v.Items[v.SelectedIndex]
}

// View renders the vulnerability list.
func (v VulnerabilityList) View() string {
	if len(v.Items) == 0 {
		return v.styles.TextMuted.Render("  No vulnerabilities found")
	}

	var lines []string
	startIdx := 0
	endIdx := len(v.Items)

	// Scrolling: keep selected item visible
	if v.Height > 0 && len(v.Items) > v.Height {
		if v.SelectedIndex >= v.Height {
			startIdx = v.SelectedIndex - v.Height + 1
		}
		endIdx = min(startIdx+v.Height, len(v.Items))
	}

	for i := startIdx; i < endIdx; i++ {
		item := v.Items[i]
		lines = append(lines, v.renderItem(item, i == v.SelectedIndex))
	}

	return strings.Join(lines, "\n")
}

func (v VulnerabilityList) renderItem(item Vulnerability, selected bool) string {
	// Status indicator
	var statusIcon string
	if item.Fixed {
		statusIcon = v.styles.TextSuccess.Render("✓")
	} else if item.Fixing {
		statusIcon = v.styles.TextMuted.Render("◌")
	} else {
		statusIcon = " "
	}

	// Selection indicator
	cursor := "  "
	if selected {
		cursor = lipgloss.NewStyle().Foreground(ColorPrimary).Render("> ")
	}

	// Severity badge
	severityBadge := v.styles.SeverityStyle(item.Severity).Render(item.Severity.String())

	// Title (truncate if needed)
	title := item.Title
	maxTitleLen := v.Width - 25
	if len(title) > maxTitleLen {
		title = title[:maxTitleLen-3] + "..."
	}

	// Can fix indicator
	fixIndicator := ""
	if item.CanAutoFix && !item.Fixed {
		fixIndicator = v.styles.TextMuted.Render(" [auto-fix]")
	}

	line := fmt.Sprintf("%s%s %s %s%s", cursor, statusIcon, severityBadge, title, fixIndicator)

	if selected {
		return v.styles.ListItemSelected.Render(line)
	}
	return v.styles.ListItem.Render(line)
}

// ProgressBar renders a progress bar.
type ProgressBar struct {
	Current int
	Total   int
	Width   int
	Label   string
	styles  Styles
}

// NewProgressBar creates a new progress bar component.
func NewProgressBar(styles Styles) ProgressBar {
	return ProgressBar{
		Width:  40,
		styles: styles,
	}
}

// SetProgress updates the progress bar values.
func (p *ProgressBar) SetProgress(current, total int) {
	p.Current = current
	p.Total = total
}

// Percent returns the progress percentage.
func (p ProgressBar) Percent() float64 {
	if p.Total == 0 {
		return 0
	}
	return float64(p.Current) / float64(p.Total)
}

// View renders the progress bar.
func (p ProgressBar) View() string {
	percent := p.Percent()
	filled := int(float64(p.Width) * percent)
	empty := p.Width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	// Color the filled portion
	coloredBar := p.styles.ProgressFilled.Render(strings.Repeat("█", filled)) +
		p.styles.ProgressEmpty.Render(strings.Repeat("░", empty))

	percentText := fmt.Sprintf("%3d%%", int(percent*100))

	var result string
	if p.Label != "" {
		result = fmt.Sprintf("%s\n[%s] %s (%d/%d)",
			p.styles.Text.Render(p.Label),
			coloredBar,
			p.styles.TextMuted.Render(percentText),
			p.Current,
			p.Total,
		)
	} else {
		result = fmt.Sprintf("[%s] %s", bar, percentText)
	}

	return result
}

// StatusBadge renders a status badge.
type StatusBadge struct {
	Status string
	styles Styles
}

// NewStatusBadge creates a new status badge.
func NewStatusBadge(status string, styles Styles) StatusBadge {
	return StatusBadge{
		Status: status,
		styles: styles,
	}
}

// View renders the status badge.
func (s StatusBadge) View() string {
	switch strings.ToLower(s.Status) {
	case "success", "passed", "fixed", "secure":
		return s.styles.BadgeSuccess.Render(s.Status)
	case "warning", "partial":
		return s.styles.BadgeWarning.Render(s.Status)
	case "error", "failed", "critical":
		return s.styles.BadgeError.Render(s.Status)
	case "info", "scanning", "checking":
		return s.styles.BadgeInfo.Render(s.Status)
	case "pending", "waiting":
		return s.styles.BadgePending.Render(s.Status)
	default:
		return s.styles.BadgeInfo.Render(s.Status)
	}
}

// HelpView renders the help/key bindings view.
type HelpView struct {
	Bindings []KeyBinding
	styles   Styles
}

// KeyBinding represents a keyboard shortcut.
type KeyBinding struct {
	Key         string
	Description string
}

// NewHelpView creates a new help view.
func NewHelpView(styles Styles) HelpView {
	return HelpView{
		styles: styles,
	}
}

// SetBindings updates the key bindings.
func (h *HelpView) SetBindings(bindings []KeyBinding) {
	h.Bindings = bindings
}

// View renders the help view.
func (h HelpView) View() string {
	if len(h.Bindings) == 0 {
		return ""
	}

	var parts []string
	for _, b := range h.Bindings {
		key := lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSecondary).
			Render(b.Key)
		desc := h.styles.TextMuted.Render(b.Description)
		parts = append(parts, fmt.Sprintf("%s %s", key, desc))
	}

	return h.styles.HelpBar.Render(strings.Join(parts, "  •  "))
}

// DependencyList renders a list of dependency checks.
type DependencyList struct {
	Checks []DependencyCheck
	styles Styles
}

// NewDependencyList creates a new dependency list.
func NewDependencyList(styles Styles) DependencyList {
	return DependencyList{
		styles: styles,
	}
}

// SetChecks updates the dependency checks.
func (d *DependencyList) SetChecks(checks []DependencyCheck) {
	d.Checks = checks
}

// View renders the dependency list.
func (d DependencyList) View() string {
	if len(d.Checks) == 0 {
		return d.styles.TextMuted.Render("  No dependencies checked yet...")
	}

	var lines []string
	for _, check := range d.Checks {
		lines = append(lines, d.renderCheck(check))
	}

	return strings.Join(lines, "\n")
}

func (d DependencyList) renderCheck(check DependencyCheck) string {
	var icon string
	var nameStyle lipgloss.Style

	if check.Found {
		icon = d.styles.TextSuccess.Render("✓")
		nameStyle = d.styles.Text
	} else if check.Error != "" {
		icon = d.styles.TextError.Render("✗")
		nameStyle = d.styles.TextError
	} else {
		icon = d.styles.TextMuted.Render("○")
		nameStyle = d.styles.TextMuted
	}

	name := nameStyle.Render(check.Name)

	var extra string
	if check.Version != "" {
		extra = d.styles.TextMuted.Render(fmt.Sprintf(" (v%s)", check.Version))
	} else if check.Error != "" {
		extra = d.styles.TextError.Render(fmt.Sprintf(" - %s", check.Error))
	} else if check.Required && !check.Found {
		extra = d.styles.TextMuted.Render(" (required)")
	}

	return fmt.Sprintf("  %s %s%s", icon, name, extra)
}

// SummaryBox renders a summary statistics box.
type SummaryBox struct {
	Title    string
	Stats    map[string]string
	Width    int
	styles   Styles
}

// NewSummaryBox creates a new summary box.
func NewSummaryBox(title string, styles Styles) SummaryBox {
	return SummaryBox{
		Title:  title,
		Stats:  make(map[string]string),
		Width:  40,
		styles: styles,
	}
}

// SetStat sets a statistic value.
func (s *SummaryBox) SetStat(key, value string) {
	s.Stats[key] = value
}

// View renders the summary box.
func (s SummaryBox) View() string {
	var lines []string

	title := s.styles.SectionHead.Render(s.Title)
	lines = append(lines, title)

	for key, value := range s.Stats {
		keyStyle := s.styles.TextMuted.Render(key + ":")
		valueStyle := s.styles.TextBold.Render(value)
		lines = append(lines, fmt.Sprintf("  %s %s", keyStyle, valueStyle))
	}

	content := strings.Join(lines, "\n")
	return s.styles.Box.Width(s.Width).Render(content)
}

// Spinner characters for animation.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner renders an animated spinner.
type Spinner struct {
	Frame  int
	Label  string
	styles Styles
}

// NewSpinner creates a new spinner.
func NewSpinner(styles Styles) Spinner {
	return Spinner{
		styles: styles,
	}
}

// Tick advances the spinner frame.
func (s *Spinner) Tick() {
	s.Frame = (s.Frame + 1) % len(spinnerFrames)
}

// View renders the spinner.
func (s Spinner) View() string {
	frame := lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Render(spinnerFrames[s.Frame])

	label := s.styles.Text.Render(s.Label)
	return fmt.Sprintf("%s %s", frame, label)
}

// Helper functions

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
