package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// RegisterAllChecks registers all 26 security checks with the registry.
func RegisterAllChecks(registry *CheckRegistry) {
	// Credential checks (CRED-001 to CRED-006)
	registry.Register(&CheckDefinition{
		ID:          "CRED-001",
		Title:       "API keys stored in plaintext",
		Description: "API keys and secrets should not be stored in plaintext configuration files",
		Category:    CategoryCredentials,
		Severity:    SeverityCritical,
		Remediation: "Use environment variables or a secrets manager for API keys",
		AutoFixable: false,
		References:  []string{"https://docs.molt.bot/configuration#secrets"},
		CheckFunc:   checkPlaintextAPIKeys,
	})

	registry.Register(&CheckDefinition{
		ID:          "CRED-002",
		Title:       "Credentials file permissions too permissive",
		Description: "Credential files should only be readable by the owner (600 or 400)",
		Category:    CategoryCredentials,
		Severity:    SeverityHigh,
		Remediation: "Run: chmod 600 ~/.clawdbot/credentials/*",
		AutoFixable: true,
		References:  []string{"https://docs.molt.bot/security"},
		CheckFunc:   checkCredentialPermissions,
	})

	registry.Register(&CheckDefinition{
		ID:          "CRED-003",
		Title:       "Session files permissions too permissive",
		Description: "Session files should only be readable by the owner",
		Category:    CategoryCredentials,
		Severity:    SeverityHigh,
		Remediation: "Run: chmod 600 ~/.clawdbot/sessions/*",
		AutoFixable: true,
		CheckFunc:   checkSessionPermissions,
	})

	registry.Register(&CheckDefinition{
		ID:          "CRED-004",
		Title:       "Credentials in shell history",
		Description: "API keys or tokens found in shell history files",
		Category:    CategoryCredentials,
		Severity:    SeverityHigh,
		Remediation: "Clear sensitive commands from shell history",
		AutoFixable: false,
		CheckFunc:   checkShellHistory,
	})

	registry.Register(&CheckDefinition{
		ID:          "CRED-005",
		Title:       "Credentials in environment variables logged",
		Description: "Environment variables with secrets may be logged",
		Category:    CategoryCredentials,
		Severity:    SeverityMedium,
		Remediation: "Use config files with proper permissions instead of env vars for secrets",
		AutoFixable: false,
		CheckFunc:   checkEnvVarLogging,
	})

	registry.Register(&CheckDefinition{
		ID:          "CRED-006",
		Title:       "Backup files contain credentials",
		Description: "Backup or temporary files may contain sensitive credentials",
		Category:    CategoryCredentials,
		Severity:    SeverityMedium,
		Remediation: "Remove backup files: rm ~/.clawdbot/*.bak ~/.clawdbot/*~",
		AutoFixable: true,
		CheckFunc:   checkBackupFiles,
	})

	// Network checks (NET-001 to NET-005)
	registry.Register(&CheckDefinition{
		ID:          "NET-001",
		Title:       "Gateway bound to all interfaces",
		Description: "Gateway is listening on 0.0.0.0, exposing it to the network",
		Category:    CategoryNetwork,
		Severity:    SeverityCritical,
		Remediation: "Set gateway.mode=local in moltbot config",
		AutoFixable: true,
		References:  []string{"https://docs.molt.bot/gateway"},
		CheckFunc:   checkGatewayBinding,
	})

	registry.Register(&CheckDefinition{
		ID:          "NET-002",
		Title:       "No authentication on gateway",
		Description: "Gateway API has no authentication enabled",
		Category:    CategoryNetwork,
		Severity:    SeverityCritical,
		Remediation: "Enable gateway authentication with a strong secret",
		AutoFixable: false,
		CheckFunc:   checkGatewayAuth,
	})

	registry.Register(&CheckDefinition{
		ID:          "NET-003",
		Title:       "Gateway using HTTP instead of HTTPS",
		Description: "Gateway traffic is not encrypted",
		Category:    CategoryNetwork,
		Severity:    SeverityHigh,
		Platforms:   []string{"linux"},
		Remediation: "Configure TLS or use a reverse proxy with HTTPS",
		AutoFixable: false,
		CheckFunc:   checkGatewayTLS,
	})

	registry.Register(&CheckDefinition{
		ID:          "NET-004",
		Title:       "Firewall not configured",
		Description: "No firewall rules detected for gateway port",
		Category:    CategoryNetwork,
		Severity:    SeverityMedium,
		Remediation: "Configure firewall to restrict gateway port access",
		AutoFixable: false,
		CheckFunc:   checkFirewall,
	})

	registry.Register(&CheckDefinition{
		ID:          "NET-005",
		Title:       "Webhook endpoints exposed",
		Description: "Webhook endpoints may be accessible without authentication",
		Category:    CategoryNetwork,
		Severity:    SeverityMedium,
		Remediation: "Ensure webhooks validate signatures",
		AutoFixable: false,
		CheckFunc:   checkWebhooks,
	})

	// Permission checks (PERM-001 to PERM-004)
	registry.Register(&CheckDefinition{
		ID:          "PERM-001",
		Title:       "Config directory permissions too permissive",
		Description: "The .clawdbot directory should not be world-readable",
		Category:    CategoryPermissions,
		Severity:    SeverityHigh,
		Remediation: "Run: chmod 700 ~/.clawdbot",
		AutoFixable: true,
		CheckFunc:   checkConfigDirPermissions,
	})

	registry.Register(&CheckDefinition{
		ID:          "PERM-002",
		Title:       "Log files contain sensitive data",
		Description: "Log files may contain API keys or personal data",
		Category:    CategoryPermissions,
		Severity:    SeverityMedium,
		Remediation: "Configure log redaction or reduce log verbosity",
		AutoFixable: false,
		CheckFunc:   checkLogSensitiveData,
	})

	registry.Register(&CheckDefinition{
		ID:          "PERM-003",
		Title:       "Running as root",
		Description: "Moltbot should not run as root user",
		Category:    CategoryPermissions,
		Severity:    SeverityCritical,
		Platforms:   []string{"linux", "darwin"},
		Remediation: "Run moltbot as a non-root user",
		AutoFixable: false,
		CheckFunc:   checkRunningAsRoot,
	})

	registry.Register(&CheckDefinition{
		ID:          "PERM-004",
		Title:       "Executable files in config directory",
		Description: "Executable files in config directory could be security risk",
		Category:    CategoryPermissions,
		Severity:    SeverityMedium,
		Remediation: "Remove executable permissions: chmod -x ~/.clawdbot/*",
		AutoFixable: true,
		CheckFunc:   checkExecutableConfigs,
	})

	// Docker checks (DOCK-001 to DOCK-003)
	registry.Register(&CheckDefinition{
		ID:          "DOCK-001",
		Title:       "Docker sandbox not enabled",
		Description: "Code execution sandbox is not using Docker isolation",
		Category:    CategoryDocker,
		Severity:    SeverityHigh,
		Remediation: "Enable Docker sandboxing in configuration",
		AutoFixable: false,
		CheckFunc:   checkDockerEnabled,
	})

	registry.Register(&CheckDefinition{
		ID:          "DOCK-002",
		Title:       "Docker running as privileged",
		Description: "Docker containers should not run with --privileged flag",
		Category:    CategoryDocker,
		Severity:    SeverityCritical,
		Remediation: "Remove privileged mode from Docker configuration",
		AutoFixable: false,
		CheckFunc:   checkDockerPrivileged,
	})

	registry.Register(&CheckDefinition{
		ID:          "DOCK-003",
		Title:       "Docker socket exposed",
		Description: "Docker socket is mounted in containers",
		Category:    CategoryDocker,
		Severity:    SeverityCritical,
		Remediation: "Do not mount Docker socket in sandbox containers",
		AutoFixable: false,
		CheckFunc:   checkDockerSocket,
	})

	// Pairing checks (PAIR-001 to PAIR-003)
	registry.Register(&CheckDefinition{
		ID:          "PAIR-001",
		Title:       "Pairing code reuse",
		Description: "Pairing codes should be single-use and expire",
		Category:    CategoryPairing,
		Severity:    SeverityMedium,
		Remediation: "Ensure pairing codes expire after use",
		AutoFixable: false,
		CheckFunc:   checkPairingCodeReuse,
	})

	registry.Register(&CheckDefinition{
		ID:          "PAIR-002",
		Title:       "Too many paired devices",
		Description: "Large number of paired devices may indicate compromise",
		Category:    CategoryPairing,
		Severity:    SeverityLow,
		Remediation: "Review and remove unused paired devices",
		AutoFixable: false,
		CheckFunc:   checkPairedDeviceCount,
	})

	registry.Register(&CheckDefinition{
		ID:          "PAIR-003",
		Title:       "Pairing without rate limiting",
		Description: "Pairing attempts should be rate limited",
		Category:    CategoryPairing,
		Severity:    SeverityMedium,
		Remediation: "Enable rate limiting for pairing requests",
		AutoFixable: false,
		CheckFunc:   checkPairingRateLimit,
	})

	// Config checks (CONF-001 to CONF-003)
	registry.Register(&CheckDefinition{
		ID:          "CONF-001",
		Title:       "Debug mode enabled in production",
		Description: "Debug mode should not be enabled in production",
		Category:    CategoryConfig,
		Severity:    SeverityMedium,
		Remediation: "Disable debug mode: moltbot config set debug false",
		AutoFixable: true,
		CheckFunc:   checkDebugMode,
	})

	registry.Register(&CheckDefinition{
		ID:          "CONF-002",
		Title:       "Verbose logging enabled",
		Description: "Verbose logging may expose sensitive information",
		Category:    CategoryConfig,
		Severity:    SeverityLow,
		Remediation: "Reduce log level in production",
		AutoFixable: true,
		CheckFunc:   checkVerboseLogging,
	})

	registry.Register(&CheckDefinition{
		ID:          "CONF-003",
		Title:       "Insecure configuration values",
		Description: "Configuration contains insecure or default values",
		Category:    CategoryConfig,
		Severity:    SeverityMedium,
		Remediation: "Review and update insecure configuration values",
		AutoFixable: false,
		CheckFunc:   checkInsecureConfig,
	})

	// Dependency checks (DEP-001 to DEP-002)
	registry.Register(&CheckDefinition{
		ID:          "DEP-001",
		Title:       "Outdated moltbot version",
		Description: "Running an outdated version with known vulnerabilities",
		Category:    CategoryDependency,
		Severity:    SeverityHigh,
		Remediation: "Update moltbot: npm install -g moltbot@latest",
		AutoFixable: false,
		CheckFunc:   checkMoltbotVersion,
	})

	registry.Register(&CheckDefinition{
		ID:          "DEP-002",
		Title:       "Vulnerable dependencies",
		Description: "Dependencies have known security vulnerabilities",
		Category:    CategoryDependency,
		Severity:    SeverityHigh,
		Remediation: "Run npm audit and update vulnerable packages",
		AutoFixable: false,
		CheckFunc:   checkVulnerableDeps,
	})
}

// Check implementations

func checkPlaintextAPIKeys(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	// Patterns for API keys and secrets
	patterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"Anthropic API Key", regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{40,}`)},
		{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{48,}`)},
		{"Discord Token", regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`)},
		{"Telegram Bot Token", regexp.MustCompile(`\d{9,10}:[A-Za-z0-9_-]{35}`)},
		{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|token)\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?`)},
	}

	// Files to check
	configDir := filepath.Join(cfg.HomeDir, ".clawdbot")
	files := []string{
		filepath.Join(configDir, "config.json"),
		filepath.Join(configDir, "config.yaml"),
		filepath.Join(configDir, "config.toml"),
	}

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue // File doesn't exist
		}

		for _, p := range patterns {
			if p.pattern.Match(content) {
				findings = append(findings, AuditFinding{
					CheckID:     "CRED-001",
					Severity:    SeverityCritical,
					Title:       "API keys stored in plaintext",
					Description: fmt.Sprintf("Found potential %s in configuration file", p.name),
					Category:    CategoryCredentials,
					File:        file,
					Remediation: "Use environment variables or a secrets manager for API keys",
					AutoFixable: false,
					Evidence:    fmt.Sprintf("Pattern matched: %s", p.name),
				})
				break
			}
		}
	}

	return findings, nil
}

func checkCredentialPermissions(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	credDir := filepath.Join(cfg.HomeDir, ".clawdbot", "credentials")
	entries, err := os.ReadDir(credDir)
	if err != nil {
		return nil, nil // Directory doesn't exist
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(credDir, entry.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		mode := info.Mode().Perm()
		if mode&0077 != 0 { // Check if group or other has any permissions
			findings = append(findings, AuditFinding{
				CheckID:     "CRED-002",
				Severity:    SeverityHigh,
				Title:       "Credentials file permissions too permissive",
				Description: fmt.Sprintf("File %s has permissions %o", entry.Name(), mode),
				Category:    CategoryCredentials,
				File:        filePath,
				Remediation: fmt.Sprintf("Run: chmod 600 %s", filePath),
				AutoFixable: true,
				Evidence:    fmt.Sprintf("Current permissions: %o", mode),
			})
		}
	}

	return findings, nil
}

func checkSessionPermissions(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	sessionDir := filepath.Join(cfg.HomeDir, ".clawdbot", "sessions")
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return nil, nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(sessionDir, entry.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			findings = append(findings, AuditFinding{
				CheckID:     "CRED-003",
				Severity:    SeverityHigh,
				Title:       "Session files permissions too permissive",
				Description: fmt.Sprintf("File %s has permissions %o", entry.Name(), mode),
				Category:    CategoryCredentials,
				File:        filePath,
				Remediation: fmt.Sprintf("Run: chmod 600 %s", filePath),
				AutoFixable: true,
				Evidence:    fmt.Sprintf("Current permissions: %o", mode),
			})
		}
	}

	return findings, nil
}

func checkShellHistory(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	historyFiles := []string{
		filepath.Join(cfg.HomeDir, ".bash_history"),
		filepath.Join(cfg.HomeDir, ".zsh_history"),
		filepath.Join(cfg.HomeDir, ".history"),
	}

	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(ANTHROPIC|OPENAI|DISCORD|TELEGRAM|SLACK).*=.*[a-zA-Z0-9_-]{20,}`),
		regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{40,}`),
		regexp.MustCompile(`sk-[a-zA-Z0-9]{48,}`),
	}

	for _, histFile := range historyFiles {
		file, err := os.Open(histFile)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			for _, pattern := range secretPatterns {
				if pattern.MatchString(line) {
					findings = append(findings, AuditFinding{
						CheckID:     "CRED-004",
						Severity:    SeverityHigh,
						Title:       "Credentials in shell history",
						Description: "Found potential API key or secret in shell history",
						Category:    CategoryCredentials,
						File:        histFile,
						Line:        lineNum,
						Remediation: "Clear sensitive commands from shell history",
						AutoFixable: false,
						Evidence:    "Secret pattern detected in history",
					})
					break
				}
			}
		}
	}

	return findings, nil
}

func checkEnvVarLogging(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	// Check for sensitive env vars that might be logged
	sensitiveVars := []string{
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"DISCORD_BOT_TOKEN",
		"TELEGRAM_BOT_TOKEN",
		"SLACK_BOT_TOKEN",
	}

	for _, envVar := range sensitiveVars {
		if os.Getenv(envVar) != "" {
			// Check if there's verbose logging enabled that might log env vars
			logFile := filepath.Join(cfg.HomeDir, ".clawdbot", "logs", "moltbot.log")
			if content, err := os.ReadFile(logFile); err == nil {
				if strings.Contains(string(content), envVar) {
					findings = append(findings, AuditFinding{
						CheckID:     "CRED-005",
						Severity:    SeverityMedium,
						Title:       "Credentials in environment variables logged",
						Description: fmt.Sprintf("Environment variable %s may be logged", envVar),
						Category:    CategoryCredentials,
						File:        logFile,
						Remediation: "Use config files with proper permissions instead of env vars for secrets",
						AutoFixable: false,
						Evidence:    fmt.Sprintf("Found reference to %s in logs", envVar),
					})
				}
			}
		}
	}

	return findings, nil
}

func checkBackupFiles(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configDir := filepath.Join(cfg.HomeDir, ".clawdbot")
	backupPatterns := []string{"*.bak", "*~", "*.backup", "*.old", "*.orig"}

	for _, pattern := range backupPatterns {
		matches, err := filepath.Glob(filepath.Join(configDir, pattern))
		if err != nil {
			continue
		}

		for _, match := range matches {
			findings = append(findings, AuditFinding{
				CheckID:     "CRED-006",
				Severity:    SeverityMedium,
				Title:       "Backup files contain credentials",
				Description: "Backup file may contain sensitive credentials",
				Category:    CategoryCredentials,
				File:        match,
				Remediation: fmt.Sprintf("Remove backup file: rm %s", match),
				AutoFixable: true,
				Evidence:    "Backup file detected",
			})
		}
	}

	return findings, nil
}

func checkGatewayBinding(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if gateway, ok := config["gateway"].(map[string]interface{}); ok {
		if mode, ok := gateway["mode"].(string); ok {
			if mode == "public" || mode == "lan" {
				findings = append(findings, AuditFinding{
					CheckID:     "NET-001",
					Severity:    SeverityCritical,
					Title:       "Gateway bound to all interfaces",
					Description: fmt.Sprintf("Gateway mode is set to '%s', exposing it to the network", mode),
					Category:    CategoryNetwork,
					File:        configFile,
					Remediation: "Set gateway.mode=local in moltbot config",
					AutoFixable: true,
					Evidence:    fmt.Sprintf("gateway.mode = %s", mode),
				})
			}
		}
	}

	// Also check if gateway is actually listening on 0.0.0.0
	cmd := exec.Command("ss", "-tlnp")
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n")
	}
	output, err := cmd.Output()
	if err == nil {
		port := strconv.Itoa(cfg.GatewayPort)
		if strings.Contains(string(output), "0.0.0.0:"+port) || strings.Contains(string(output), "*:"+port) {
			findings = append(findings, AuditFinding{
				CheckID:     "NET-001",
				Severity:    SeverityCritical,
				Title:       "Gateway bound to all interfaces",
				Description: "Gateway is actively listening on all network interfaces",
				Category:    CategoryNetwork,
				Remediation: "Set gateway.mode=local in moltbot config",
				AutoFixable: true,
				Evidence:    "Gateway listening on 0.0.0.0",
			})
		}
	}

	return findings, nil
}

func checkGatewayAuth(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if gateway, ok := config["gateway"].(map[string]interface{}); ok {
		authEnabled := false
		if auth, ok := gateway["auth"].(map[string]interface{}); ok {
			if enabled, ok := auth["enabled"].(bool); ok && enabled {
				authEnabled = true
			}
		}

		if !authEnabled {
			// Only critical if gateway is not in local mode
			mode, _ := gateway["mode"].(string)
			if mode != "local" {
				findings = append(findings, AuditFinding{
					CheckID:     "NET-002",
					Severity:    SeverityCritical,
					Title:       "No authentication on gateway",
					Description: "Gateway API has no authentication enabled while exposed to network",
					Category:    CategoryNetwork,
					File:        configFile,
					Remediation: "Enable gateway authentication with a strong secret",
					AutoFixable: false,
					Evidence:    "gateway.auth.enabled is false or not set",
				})
			}
		}
	}

	return findings, nil
}

func checkGatewayTLS(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	if runtime.GOOS != "linux" {
		return nil, nil // Skip on macOS where localhost is typically used
	}

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if gateway, ok := config["gateway"].(map[string]interface{}); ok {
		mode, _ := gateway["mode"].(string)
		tlsEnabled := false

		if tls, ok := gateway["tls"].(map[string]interface{}); ok {
			if enabled, ok := tls["enabled"].(bool); ok && enabled {
				tlsEnabled = true
			}
		}

		if mode != "local" && !tlsEnabled {
			findings = append(findings, AuditFinding{
				CheckID:     "NET-003",
				Severity:    SeverityHigh,
				Title:       "Gateway using HTTP instead of HTTPS",
				Description: "Gateway traffic is not encrypted while exposed to network",
				Category:    CategoryNetwork,
				File:        configFile,
				Remediation: "Configure TLS or use a reverse proxy with HTTPS",
				AutoFixable: false,
				Evidence:    "TLS not enabled in gateway config",
			})
		}
	}

	return findings, nil
}

func checkFirewall(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	port := strconv.Itoa(cfg.GatewayPort)
	firewallConfigured := false

	if runtime.GOOS == "darwin" {
		// Check macOS firewall
		cmd := exec.Command("pfctl", "-sr")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), port) {
			firewallConfigured = true
		}

		// Check application firewall
		cmd = exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
		output, err = cmd.Output()
		if err == nil && strings.Contains(string(output), "enabled") {
			firewallConfigured = true
		}
	} else if runtime.GOOS == "linux" {
		// Check iptables
		cmd := exec.Command("iptables", "-L", "-n")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), port) {
			firewallConfigured = true
		}

		// Check ufw
		cmd = exec.Command("ufw", "status")
		output, err = cmd.Output()
		if err == nil && strings.Contains(string(output), "active") {
			firewallConfigured = true
		}
	}

	if !firewallConfigured {
		findings = append(findings, AuditFinding{
			CheckID:     "NET-004",
			Severity:    SeverityMedium,
			Title:       "Firewall not configured",
			Description: "No firewall rules detected for gateway port",
			Category:    CategoryNetwork,
			Remediation: "Configure firewall to restrict gateway port access",
			AutoFixable: false,
			Evidence:    fmt.Sprintf("No firewall rules found for port %s", port),
		})
	}

	return findings, nil
}

func checkWebhooks(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	// Check for webhook configurations without signature validation
	channels := []string{"telegram", "discord", "slack"}
	for _, channel := range channels {
		if ch, ok := config[channel].(map[string]interface{}); ok {
			if webhook, ok := ch["webhook"].(map[string]interface{}); ok {
				if _, hasSecret := webhook["secret"]; !hasSecret {
					findings = append(findings, AuditFinding{
						CheckID:     "NET-005",
						Severity:    SeverityMedium,
						Title:       "Webhook endpoints exposed",
						Description: fmt.Sprintf("%s webhook configured without signature secret", channel),
						Category:    CategoryNetwork,
						File:        configFile,
						Remediation: "Ensure webhooks validate signatures",
						AutoFixable: false,
						Evidence:    fmt.Sprintf("%s.webhook.secret not configured", channel),
					})
				}
			}
		}
	}

	return findings, nil
}

func checkConfigDirPermissions(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configDir := filepath.Join(cfg.HomeDir, ".clawdbot")
	info, err := os.Stat(configDir)
	if err != nil {
		return nil, nil
	}

	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		findings = append(findings, AuditFinding{
			CheckID:     "PERM-001",
			Severity:    SeverityHigh,
			Title:       "Config directory permissions too permissive",
			Description: fmt.Sprintf("Directory has permissions %o", mode),
			Category:    CategoryPermissions,
			File:        configDir,
			Remediation: "Run: chmod 700 ~/.clawdbot",
			AutoFixable: true,
			Evidence:    fmt.Sprintf("Current permissions: %o", mode),
		})
	}

	return findings, nil
}

func checkLogSensitiveData(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	logDir := filepath.Join(cfg.HomeDir, ".clawdbot", "logs")
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{40,}`),
		regexp.MustCompile(`sk-[a-zA-Z0-9]{48,}`),
		regexp.MustCompile(`(?i)password\s*[=:]\s*[^\s]+`),
		regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_-]+`),
	}

	err := filepath.WalkDir(logDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".log") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		for _, pattern := range secretPatterns {
			if pattern.Match(content) {
				findings = append(findings, AuditFinding{
					CheckID:     "PERM-002",
					Severity:    SeverityMedium,
					Title:       "Log files contain sensitive data",
					Description: "Log file may contain API keys or secrets",
					Category:    CategoryPermissions,
					File:        path,
					Remediation: "Configure log redaction or reduce log verbosity",
					AutoFixable: false,
					Evidence:    "Secret pattern detected in logs",
				})
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return findings, nil
}

func checkRunningAsRoot(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	if os.Geteuid() == 0 {
		findings = append(findings, AuditFinding{
			CheckID:     "PERM-003",
			Severity:    SeverityCritical,
			Title:       "Running as root",
			Description: "Security scanner is running as root user",
			Category:    CategoryPermissions,
			Remediation: "Run moltbot as a non-root user",
			AutoFixable: false,
			Evidence:    "Effective UID is 0",
		})
	}

	return findings, nil
}

func checkExecutableConfigs(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configDir := filepath.Join(cfg.HomeDir, ".clawdbot")
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return nil, nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(configDir, entry.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		mode := info.Mode()
		if mode&0111 != 0 && !strings.HasSuffix(entry.Name(), ".sh") {
			findings = append(findings, AuditFinding{
				CheckID:     "PERM-004",
				Severity:    SeverityMedium,
				Title:       "Executable files in config directory",
				Description: fmt.Sprintf("File %s has executable permissions", entry.Name()),
				Category:    CategoryPermissions,
				File:        filePath,
				Remediation: fmt.Sprintf("Run: chmod -x %s", filePath),
				AutoFixable: true,
				Evidence:    fmt.Sprintf("Permissions: %o", mode.Perm()),
			})
		}
	}

	return findings, nil
}

func checkDockerEnabled(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if sandbox, ok := config["sandbox"].(map[string]interface{}); ok {
		if enabled, ok := sandbox["docker"].(bool); ok && !enabled {
			findings = append(findings, AuditFinding{
				CheckID:     "DOCK-001",
				Severity:    SeverityHigh,
				Title:       "Docker sandbox not enabled",
				Description: "Code execution sandbox is not using Docker isolation",
				Category:    CategoryDocker,
				File:        configFile,
				Remediation: "Enable Docker sandboxing in configuration",
				AutoFixable: false,
				Evidence:    "sandbox.docker is disabled",
			})
		}
	}

	return findings, nil
}

func checkDockerPrivileged(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if sandbox, ok := config["sandbox"].(map[string]interface{}); ok {
		if docker, ok := sandbox["docker"].(map[string]interface{}); ok {
			if privileged, ok := docker["privileged"].(bool); ok && privileged {
				findings = append(findings, AuditFinding{
					CheckID:     "DOCK-002",
					Severity:    SeverityCritical,
					Title:       "Docker running as privileged",
					Description: "Docker containers are configured to run with privileged mode",
					Category:    CategoryDocker,
					File:        configFile,
					Remediation: "Remove privileged mode from Docker configuration",
					AutoFixable: false,
					Evidence:    "sandbox.docker.privileged is true",
				})
			}
		}
	}

	return findings, nil
}

func checkDockerSocket(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if sandbox, ok := config["sandbox"].(map[string]interface{}); ok {
		if docker, ok := sandbox["docker"].(map[string]interface{}); ok {
			if mounts, ok := docker["mounts"].([]interface{}); ok {
				for _, mount := range mounts {
					if m, ok := mount.(string); ok {
						if strings.Contains(m, "docker.sock") {
							findings = append(findings, AuditFinding{
								CheckID:     "DOCK-003",
								Severity:    SeverityCritical,
								Title:       "Docker socket exposed",
								Description: "Docker socket is mounted in sandbox containers",
								Category:    CategoryDocker,
								File:        configFile,
								Remediation: "Do not mount Docker socket in sandbox containers",
								AutoFixable: false,
								Evidence:    fmt.Sprintf("Mount includes docker.sock: %s", m),
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

func checkPairingCodeReuse(cfg *ScanConfig) ([]AuditFinding, error) {
	// This check would need to examine pairing logs or state
	// Placeholder implementation
	return nil, nil
}

func checkPairedDeviceCount(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	pairingFile := filepath.Join(cfg.HomeDir, ".clawdbot", "pairing.json")
	content, err := os.ReadFile(pairingFile)
	if err != nil {
		return nil, nil
	}

	var pairing map[string]interface{}
	if err := json.Unmarshal(content, &pairing); err != nil {
		return nil, nil
	}

	if devices, ok := pairing["devices"].([]interface{}); ok {
		if len(devices) > 10 {
			findings = append(findings, AuditFinding{
				CheckID:     "PAIR-002",
				Severity:    SeverityLow,
				Title:       "Too many paired devices",
				Description: fmt.Sprintf("Found %d paired devices", len(devices)),
				Category:    CategoryPairing,
				File:        pairingFile,
				Remediation: "Review and remove unused paired devices",
				AutoFixable: false,
				Evidence:    fmt.Sprintf("%d devices paired", len(devices)),
			})
		}
	}

	return findings, nil
}

func checkPairingRateLimit(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if pairing, ok := config["pairing"].(map[string]interface{}); ok {
		if rateLimit, ok := pairing["rateLimit"].(map[string]interface{}); ok {
			if enabled, ok := rateLimit["enabled"].(bool); ok && !enabled {
				findings = append(findings, AuditFinding{
					CheckID:     "PAIR-003",
					Severity:    SeverityMedium,
					Title:       "Pairing without rate limiting",
					Description: "Rate limiting is disabled for pairing requests",
					Category:    CategoryPairing,
					File:        configFile,
					Remediation: "Enable rate limiting for pairing requests",
					AutoFixable: false,
					Evidence:    "pairing.rateLimit.enabled is false",
				})
			}
		}
	}

	return findings, nil
}

func checkDebugMode(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if debug, ok := config["debug"].(bool); ok && debug {
		findings = append(findings, AuditFinding{
			CheckID:     "CONF-001",
			Severity:    SeverityMedium,
			Title:       "Debug mode enabled in production",
			Description: "Debug mode is enabled which may expose sensitive information",
			Category:    CategoryConfig,
			File:        configFile,
			Remediation: "Disable debug mode: moltbot config set debug false",
			AutoFixable: true,
			Evidence:    "debug is true",
		})
	}

	return findings, nil
}

func checkVerboseLogging(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	if logLevel, ok := config["logLevel"].(string); ok {
		if logLevel == "trace" || logLevel == "debug" {
			findings = append(findings, AuditFinding{
				CheckID:     "CONF-002",
				Severity:    SeverityLow,
				Title:       "Verbose logging enabled",
				Description: fmt.Sprintf("Log level is set to '%s' which may expose sensitive information", logLevel),
				Category:    CategoryConfig,
				File:        configFile,
				Remediation: "Reduce log level in production",
				AutoFixable: true,
				Evidence:    fmt.Sprintf("logLevel is '%s'", logLevel),
			})
		}
	}

	return findings, nil
}

func checkInsecureConfig(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	configFile := filepath.Join(cfg.HomeDir, ".clawdbot", "config.json")
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil
	}

	// Check for insecure defaults
	insecurePatterns := []struct {
		path  string
		value interface{}
		desc  string
	}{
		{"allowUnsafeEval", true, "Unsafe eval is enabled"},
		{"disableSecurityChecks", true, "Security checks are disabled"},
		{"trustAllCerts", true, "TLS certificate verification is disabled"},
	}

	for _, p := range insecurePatterns {
		if val, ok := config[p.path]; ok && val == p.value {
			findings = append(findings, AuditFinding{
				CheckID:     "CONF-003",
				Severity:    SeverityMedium,
				Title:       "Insecure configuration values",
				Description: p.desc,
				Category:    CategoryConfig,
				File:        configFile,
				Remediation: "Review and update insecure configuration values",
				AutoFixable: false,
				Evidence:    fmt.Sprintf("%s is %v", p.path, p.value),
			})
		}
	}

	return findings, nil
}

func checkMoltbotVersion(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	cmd := exec.Command("moltbot", "--version")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	version := strings.TrimSpace(string(output))

	// Check against npm for latest version
	cmd = exec.Command("npm", "view", "moltbot", "version")
	latestOutput, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	latest := strings.TrimSpace(string(latestOutput))

	if version != latest {
		findings = append(findings, AuditFinding{
			CheckID:     "DEP-001",
			Severity:    SeverityHigh,
			Title:       "Outdated moltbot version",
			Description: fmt.Sprintf("Running version %s, latest is %s", version, latest),
			Category:    CategoryDependency,
			Remediation: "Update moltbot: npm install -g moltbot@latest",
			AutoFixable: false,
			Evidence:    fmt.Sprintf("Current: %s, Latest: %s", version, latest),
		})
	}

	return findings, nil
}

func checkVulnerableDeps(cfg *ScanConfig) ([]AuditFinding, error) {
	var findings []AuditFinding

	// Check if there's a package.json in config dir for any extensions
	packageFile := filepath.Join(cfg.HomeDir, ".clawdbot", "extensions", "package.json")
	if _, err := os.Stat(packageFile); err != nil {
		return nil, nil
	}

	cmd := exec.Command("npm", "audit", "--json")
	cmd.Dir = filepath.Dir(packageFile)
	output, err := cmd.Output()
	if err == nil {
		var auditResult map[string]interface{}
		if err := json.Unmarshal(output, &auditResult); err == nil {
			if vulns, ok := auditResult["vulnerabilities"].(map[string]interface{}); ok {
				if len(vulns) > 0 {
					findings = append(findings, AuditFinding{
						CheckID:     "DEP-002",
						Severity:    SeverityHigh,
						Title:       "Vulnerable dependencies",
						Description: fmt.Sprintf("Found %d vulnerable dependencies", len(vulns)),
						Category:    CategoryDependency,
						File:        packageFile,
						Remediation: "Run npm audit and update vulnerable packages",
						AutoFixable: false,
						Evidence:    fmt.Sprintf("%d vulnerabilities found", len(vulns)),
					})
				}
			}
		}
	}

	return findings, nil
}
