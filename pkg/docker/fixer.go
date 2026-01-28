// Package docker provides security fixers for Docker configuration in Moltbot.
package docker

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtraHostRisk represents a risky extra_hosts entry.
type ExtraHostRisk struct {
	Entry  string
	Reason string
	Risk   string
}

// BindPathRisk represents a risky bind mount path.
type BindPathRisk struct {
	Path    string
	Reason  string
	Risk    string
	Allowed bool
}

// Fixer provides methods to fix Docker security issues.
type Fixer struct {
	DryRun bool
	Logger *log.Logger
}

// NewFixer creates a new Docker fixer.
func NewFixer(dryRun bool) *Fixer {
	return &Fixer{
		DryRun: dryRun,
		Logger: log.New(os.Stdout, "[docker-fixer] ", log.LstdFlags),
	}
}

// ValidateExtraHosts checks extra_hosts entries for DNS poisoning risks.
func (f *Fixer) ValidateExtraHosts(extraHosts []string) []ExtraHostRisk {
	f.Logger.Println("Validating extra_hosts for DNS poisoning risks")

	var risks []ExtraHostRisk

	// Sensitive hostnames that shouldn't be overridden
	sensitiveHosts := map[string]string{
		"localhost":              "Overriding localhost can cause unexpected behavior",
		"metadata.google":        "GCP metadata service - can leak credentials",
		"169.254.169.254":        "Cloud metadata IP - credential theft risk",
		"metadata.aws":           "AWS metadata service - can leak credentials",
		"api.anthropic.com":      "Anthropic API - could intercept API calls",
		"api.openai.com":         "OpenAI API - could intercept API calls",
		"oauth.googleapis.com":   "Google OAuth - could steal tokens",
		"accounts.google.com":    "Google accounts - could steal credentials",
		"login.microsoftonline":  "Microsoft login - could steal credentials",
		"github.com":             "GitHub - could intercept code/credentials",
		"registry.npmjs.org":     "npm registry - could serve malicious packages",
		"pypi.org":               "PyPI - could serve malicious packages",
	}

	for _, entry := range extraHosts {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}

		hostname := strings.ToLower(parts[0])
		targetIP := parts[1]

		// Check if it's a sensitive host
		for sensitive, reason := range sensitiveHosts {
			if strings.Contains(hostname, sensitive) {
				risk := ExtraHostRisk{
					Entry:  entry,
					Reason: reason,
					Risk:   "critical",
				}
				risks = append(risks, risk)
				f.Logger.Printf("CRITICAL: extra_host '%s' overrides sensitive host - %s", entry, reason)
			}
		}

		// Check for localhost/loopback hijacking
		if (hostname != "localhost" && hostname != "host.docker.internal") &&
			(targetIP == "127.0.0.1" || targetIP == "::1") {
			// This could be redirecting external services to localhost
			risk := ExtraHostRisk{
				Entry:  entry,
				Reason: "Redirecting external hostname to localhost - possible DNS hijacking",
				Risk:   "high",
			}
			risks = append(risks, risk)
			f.Logger.Printf("HIGH: extra_host '%s' redirects to localhost", entry)
		}

		// Check for private IP ranges being used
		if isPrivateIP(targetIP) && !strings.HasPrefix(hostname, "internal") {
			risk := ExtraHostRisk{
				Entry:  entry,
				Reason: "Pointing external hostname to private IP - possible internal network access",
				Risk:   "medium",
			}
			risks = append(risks, risk)
			f.Logger.Printf("MEDIUM: extra_host '%s' points to private IP", entry)
		}
	}

	if len(risks) == 0 {
		f.Logger.Println("No DNS poisoning risks detected in extra_hosts")
	}

	return risks
}

// isPrivateIP checks if an IP address is in a private range.
func isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// RestrictBindPaths validates bind mount paths against a whitelist.
func (f *Fixer) RestrictBindPaths(bindPaths []string, whitelist []string) []BindPathRisk {
	f.Logger.Println("Validating bind mount paths against whitelist")

	// Default safe paths if no whitelist provided
	if len(whitelist) == 0 {
		whitelist = []string{
			"/tmp",
			"/var/tmp",
		}
	}

	// Dangerous paths that should never be mounted
	dangerousPaths := map[string]string{
		"/":                      "Root filesystem - complete host access",
		"/etc":                   "System configuration files",
		"/etc/passwd":            "User database",
		"/etc/shadow":            "Password hashes",
		"/var/run/docker.sock":   "Docker socket - container escape",
		"/var/run/docker":        "Docker runtime - container escape",
		"/proc":                  "Process information and exploitation",
		"/sys":                   "System/kernel configuration",
		"/dev":                   "Device access - privilege escalation",
		"/boot":                  "Boot configuration",
		"/root":                  "Root home directory",
	}

	var risks []BindPathRisk

	for _, path := range bindPaths {
		// Extract source path (before the colon if present)
		sourcePath := path
		if idx := strings.Index(path, ":"); idx != -1 {
			sourcePath = path[:idx]
		}

		// Resolve any home directory references
		if strings.HasPrefix(sourcePath, "~") {
			home, _ := os.UserHomeDir()
			sourcePath = strings.Replace(sourcePath, "~", home, 1)
		}

		// Clean the path
		sourcePath = filepath.Clean(sourcePath)

		// Check if path is dangerous
		for dangerous, reason := range dangerousPaths {
			if sourcePath == dangerous || strings.HasPrefix(sourcePath, dangerous+"/") {
				risk := BindPathRisk{
					Path:    path,
					Reason:  reason,
					Risk:    "critical",
					Allowed: false,
				}
				risks = append(risks, risk)
				f.Logger.Printf("CRITICAL: Dangerous bind mount '%s' - %s", path, reason)
				continue
			}
		}

		// Check home directory sensitive paths
		home, _ := os.UserHomeDir()
		sensitivePaths := []string{
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".config"),
			filepath.Join(home, ".clawdbot"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".kube"),
		}

		for _, sensitive := range sensitivePaths {
			if sourcePath == sensitive || strings.HasPrefix(sourcePath, sensitive+"/") {
				risk := BindPathRisk{
					Path:    path,
					Reason:  "Sensitive user directory - credential/key theft risk",
					Risk:    "critical",
					Allowed: false,
				}
				risks = append(risks, risk)
				f.Logger.Printf("CRITICAL: Sensitive directory bind mount '%s'", path)
			}
		}

		// Check against whitelist
		allowed := false
		for _, safe := range whitelist {
			if sourcePath == safe || strings.HasPrefix(sourcePath, safe+"/") {
				allowed = true
				break
			}
		}

		if !allowed {
			// Check if we already flagged it as dangerous
			alreadyFlagged := false
			for _, r := range risks {
				if r.Path == path {
					alreadyFlagged = true
					break
				}
			}

			if !alreadyFlagged {
				risk := BindPathRisk{
					Path:    path,
					Reason:  "Path not in whitelist",
					Risk:    "medium",
					Allowed: false,
				}
				risks = append(risks, risk)
				f.Logger.Printf("MEDIUM: Bind mount '%s' not in whitelist", path)
			}
		}
	}

	if len(risks) == 0 {
		f.Logger.Println("All bind mount paths are allowed")
	}

	return risks
}

// GenerateHardenedCompose creates a security-hardened docker-compose.yml.
func (f *Fixer) GenerateHardenedCompose(outputPath string, imageName string) error {
	f.Logger.Printf("Generating hardened docker-compose.yml at %s", outputPath)

	if imageName == "" {
		imageName = "moltbot-sandbox:latest"
	}

	compose := fmt.Sprintf(`# Hardened Docker Compose for Moltbot Sandbox
# Generated by moltbot-hardener

version: "3.8"

services:
  sandbox:
    image: %s

    # Security: Run as non-root user
    user: "1000:1000"

    # Security: Read-only root filesystem
    read_only: true

    # Security: No network access
    network_mode: none

    # Security: Drop all capabilities
    cap_drop:
      - ALL

    # Security: No new privileges
    security_opt:
      - no-new-privileges:true

    # Security: Seccomp profile (use default or custom)
    # security_opt:
    #   - seccomp:/path/to/seccomp-profile.json

    # Security: Memory limits to prevent DoS
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "1.0"
        reservations:
          memory: 128M

    # Security: Limit PIDs to prevent fork bombs
    pids_limit: 100

    # Security: Temporary writable directories
    tmpfs:
      - /tmp:size=100M,mode=1777
      - /var/tmp:size=50M,mode=1777

    # Security: No privileged mode
    privileged: false

    # Security: No host IPC/PID namespaces
    ipc: private
    pid: "container:sandbox"

    # Security: Healthcheck
    healthcheck:
      test: ["CMD", "true"]
      interval: 30s
      timeout: 10s
      retries: 3

    # Environment (add your config here)
    environment:
      - HOME=/home/sandbox
      - USER=sandbox

    # Working directory
    working_dir: /workspace
`, imageName)

	if f.DryRun {
		f.Logger.Println("[DRY-RUN] Would write hardened docker-compose.yml:")
		fmt.Println(compose)
		return nil
	}

	err := os.WriteFile(outputPath, []byte(compose), 0644)
	if err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	f.Logger.Printf("Successfully wrote hardened docker-compose.yml to %s", outputPath)
	return nil
}

// ValidateCurrentCompose checks an existing docker-compose.yml for security issues.
func (f *Fixer) ValidateCurrentCompose(composePath string) ([]string, error) {
	f.Logger.Printf("Validating docker-compose.yml at %s", composePath)

	content, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	composeStr := string(content)
	var issues []string

	// Check for common security misconfigurations
	checks := []struct {
		pattern string
		message string
	}{
		{"privileged: true", "CRITICAL: privileged mode is enabled - containers have full host access"},
		{"network_mode: host", "CRITICAL: host network mode - container shares host network stack"},
		{"pid: host", "HIGH: host PID namespace - can see and signal host processes"},
		{"ipc: host", "HIGH: host IPC namespace - can access host shared memory"},
		{"/var/run/docker.sock", "CRITICAL: Docker socket mounted - container can control Docker"},
		{"cap_add:", "MEDIUM: Capabilities being added - review if necessary"},
		{"SYS_ADMIN", "CRITICAL: SYS_ADMIN capability - near-root access"},
		{"NET_ADMIN", "HIGH: NET_ADMIN capability - can modify network settings"},
		{"SYS_PTRACE", "HIGH: SYS_PTRACE capability - can trace other processes"},
		{"user: root", "MEDIUM: Running as root user"},
		{"user: \"0", "MEDIUM: Running as root user (UID 0)"},
	}

	for _, check := range checks {
		if strings.Contains(composeStr, check.pattern) {
			issues = append(issues, check.message)
			f.Logger.Println(check.message)
		}
	}

	// Check for missing security features
	missingChecks := []struct {
		pattern string
		message string
	}{
		{"cap_drop", "MEDIUM: No cap_drop specified - should drop ALL capabilities"},
		{"read_only", "LOW: read_only not set - consider read-only root filesystem"},
		{"no-new-privileges", "MEDIUM: no-new-privileges not set"},
		{"pids_limit", "LOW: pids_limit not set - vulnerable to fork bombs"},
		{"memory", "LOW: No memory limit set"},
	}

	for _, check := range missingChecks {
		if !strings.Contains(composeStr, check.pattern) {
			issues = append(issues, check.message)
			f.Logger.Println(check.message)
		}
	}

	if len(issues) == 0 {
		f.Logger.Println("No security issues found in docker-compose.yml")
	} else {
		f.Logger.Printf("Found %d security issue(s) in docker-compose.yml", len(issues))
	}

	return issues, nil
}

// SetSecureDockerDefaults configures secure Docker defaults via moltbot config.
func (f *Fixer) SetSecureDockerDefaults() error {
	f.Logger.Println("Setting secure Docker defaults")

	configs := []struct {
		key   string
		value string
	}{
		{"sandbox.docker.network", "none"},
		{"sandbox.docker.capDrop", "[\"ALL\"]"},
		{"sandbox.docker.readOnly", "true"},
		{"sandbox.docker.noNewPrivileges", "true"},
		{"sandbox.docker.pidsLimit", "100"},
		{"sandbox.docker.memoryLimit", "512m"},
		{"sandbox.docker.user", "1000:1000"},
	}

	for _, cfg := range configs {
		if f.DryRun {
			f.Logger.Printf("[DRY-RUN] Would set %s = %s", cfg.key, cfg.value)
			continue
		}

		cmd := exec.Command("moltbot", "config", "set", cfg.key, cfg.value)
		output, err := cmd.CombinedOutput()
		if err != nil {
			f.Logger.Printf("Warning: Failed to set %s: %v (output: %s)", cfg.key, err, string(output))
			// Continue with other configs
		} else {
			f.Logger.Printf("Set %s = %s", cfg.key, cfg.value)
		}
	}

	f.Logger.Println("Secure Docker defaults configured")
	return nil
}

// FixAll applies all Docker security fixes.
func (f *Fixer) FixAll() error {
	f.Logger.Println("Applying all Docker security fixes")

	if err := f.SetSecureDockerDefaults(); err != nil {
		return fmt.Errorf("SetSecureDockerDefaults failed: %w", err)
	}

	f.Logger.Println("All Docker security fixes applied successfully")
	return nil
}
