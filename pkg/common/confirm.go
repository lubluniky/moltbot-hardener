// Package common provides shared utilities for moltbot-hardener.
package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ConfirmPrompt asks the user for yes/no confirmation.
// Returns true if user confirms, false otherwise.
func ConfirmPrompt(message string) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n%s [y/N]: ", message)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// ConfirmPromptWithDefault asks for confirmation with a default value.
func ConfirmPromptWithDefault(message string, defaultYes bool) bool {
	reader := bufio.NewReader(os.Stdin)

	prompt := "[y/N]"
	if defaultYes {
		prompt = "[Y/n]"
	}

	fmt.Printf("\n%s %s: ", message, prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response == "" {
		return defaultYes
	}
	return response == "y" || response == "yes"
}

// ConfirmDangerous asks for confirmation on dangerous operations.
// Requires typing "yes" explicitly.
func ConfirmDangerous(message string) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n⚠️  %s\n", message)
	fmt.Print("Type 'yes' to confirm: ")
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	return strings.TrimSpace(strings.ToLower(response)) == "yes"
}

// SelectOption presents a menu and returns the selected index.
func SelectOption(message string, options []string) int {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n%s\n", message)
	for i, opt := range options {
		fmt.Printf("  [%d] %s\n", i+1, opt)
	}
	fmt.Print("Select option: ")

	response, err := reader.ReadString('\n')
	if err != nil {
		return -1
	}

	response = strings.TrimSpace(response)
	var selected int
	_, err = fmt.Sscanf(response, "%d", &selected)
	if err != nil || selected < 1 || selected > len(options) {
		return -1
	}

	return selected - 1
}

// FixDecision represents user's decision about a fix.
type FixDecision int

const (
	FixDecisionSkip FixDecision = iota
	FixDecisionApply
	FixDecisionApplyAll
	FixDecisionAbort
)

// AskFixDecision asks the user what to do with a specific fix.
func AskFixDecision(vulnID, title, description string) FixDecision {
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("🔧 %s: %s\n", vulnID, title)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("%s\n\n", description)

	options := []string{
		"Apply this fix",
		"Skip this fix",
		"Apply all remaining fixes",
		"Abort (don't apply any more fixes)",
	}

	selected := SelectOption("What would you like to do?", options)

	switch selected {
	case 0:
		return FixDecisionApply
	case 1:
		return FixDecisionSkip
	case 2:
		return FixDecisionApplyAll
	case 3:
		return FixDecisionAbort
	default:
		return FixDecisionSkip
	}
}
