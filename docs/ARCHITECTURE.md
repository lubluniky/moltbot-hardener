# Architecture

This document describes how moltbot-hardener is designed and how it performs security scanning and remediation.

## Overview

```
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|  Configuration   |---->|     Scanner      |---->|     Reporter     |
|     Loader       |     |      Engine      |     |                  |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
         |                       |                        |
         v                       v                        v
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|  Config Parser   |     |  Check Registry  |     |    TUI/CLI       |
|  (JSON5/YAML)    |     |  (26 Checks)     |     |    Output        |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
                                 |
                                 v
                         +------------------+
                         |                  |
                         |     Fixer        |
                         |     Engine       |
                         |                  |
                         +------------------+
```

## Components

### 1. Configuration Loader (`pkg/config/`)

Responsible for discovering and loading moltbot configurations:

```go
type ConfigLoader struct {
    ConfigPath string
    StateDir   string
    Env        map[string]string
}

func (l *ConfigLoader) Load() (*MoltbotConfig, error)
func (l *ConfigLoader) ResolveIncludes(cfg *MoltbotConfig) error
func (l *ConfigLoader) ExpandEnvVars(cfg *MoltbotConfig) error
```

**Features:**
- Auto-discovers config from `~/.moltbot/moltbot.json` or `$CLAWDBOT_STATE_DIR`
- Supports JSON5 format (comments, trailing commas)
- Resolves `$include` directives recursively
- Expands `${ENV_VAR}` references
- Validates schema against moltbot's expected structure

### 2. Scanner Engine (`pkg/scanner/`)

Orchestrates vulnerability checks:

```go
type Scanner struct {
    Config   *MoltbotConfig
    StateDir string
    Checks   []Check
    Options  ScanOptions
}

type ScanOptions struct {
    IncludeFilesystem bool
    IncludeChannels   bool
    DeepProbe         bool
    TimeoutMs         int
}

func (s *Scanner) Scan(ctx context.Context) (*ScanReport, error)
```

**Scan Phases:**
1. **Configuration Analysis** - Parse and validate config structure
2. **Gateway Security** - Check network exposure, auth, bind settings
3. **Channel Security** - Analyze DM/group policies per channel
4. **Tool Security** - Review sandbox, elevated, and tool policies
5. **Filesystem Security** - Check permissions on sensitive paths
6. **Deep Probe** (optional) - Live connectivity tests

### 3. Check Registry (`pkg/checks/`)

Each vulnerability check implements the `Check` interface:

```go
type Check interface {
    ID() string
    Name() string
    Severity() Severity
    Category() Category
    Description() string
    Run(ctx *CheckContext) ([]Finding, error)
    CanFix() bool
    Fix(ctx *FixContext) error
}

type CheckContext struct {
    Config     *MoltbotConfig
    ConfigPath string
    StateDir   string
    Env        map[string]string
    Platform   string
}
```

**Categories:**
- `gateway` - Network and authentication
- `channels` - DM/group policies and allowlists
- `tools` - Sandbox, elevated mode, tool policies
- `filesystem` - Permissions and path security
- `models` - LLM configuration hygiene
- `plugins` - Extension trust boundaries

### 4. Finding Structure

```go
type Finding struct {
    CheckID      string
    Severity     Severity
    Title        string
    Detail       string
    Remediation  string
    AffectedPath string
    CanAutoFix   bool
}

type Severity int

const (
    SeverityInfo Severity = iota
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)
```

### 5. Fixer Engine (`pkg/fixer/`)

Applies remediations for fixable findings:

```go
type Fixer struct {
    Config     *MoltbotConfig
    ConfigPath string
    StateDir   string
    DryRun     bool
    Backup     bool
}

type FixResult struct {
    CheckID   string
    Applied   bool
    Skipped   string
    Error     error
    Changes   []Change
}

type Change struct {
    Type    ChangeType  // ConfigSet, ConfigDelete, Chmod, CreateFile, etc.
    Path    string
    OldValue interface{}
    NewValue interface{}
}
```

**Fix Types:**
- **Config mutations** - Set/delete config keys
- **Permission fixes** - chmod files/directories
- **File creation** - Generate missing secure files
- **Token generation** - Create secure random tokens

### 6. Reporter (`pkg/reporter/`)

Formats scan results for various outputs:

```go
type Reporter interface {
    Report(report *ScanReport, w io.Writer) error
}

// Implementations
type CLIReporter struct{}      // Pretty terminal output
type JSONReporter struct{}     // Machine-readable JSON
type MarkdownReporter struct{}  // Documentation format
type HTMLReporter struct{}      // Web report
```

### 7. TUI (`internal/tui/`)

Interactive terminal interface using bubbletea:

```go
type Model struct {
    scanner   *Scanner
    findings  []Finding
    selected  int
    scanning  bool
    fixing    bool
}

func (m Model) Init() tea.Cmd
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd)
func (m Model) View() string
```

## Data Flow

### Scan Flow

```
1. Load Config
   |
   v
2. Resolve Includes & Env Vars
   |
   v
3. For each Check in Registry:
   |
   +-> Run Check
   |     |
   |     v
   |   Collect Findings
   |     |
   +<----+
   |
   v
4. Aggregate Findings
   |
   v
5. Sort by Severity
   |
   v
6. Generate Report
```

### Fix Flow

```
1. Select Finding(s) to Fix
   |
   v
2. Create Backup (if enabled)
   |
   v
3. For each Finding:
   |
   +-> Check.CanFix()?
   |     |
   |   Yes -> Check.Fix()
   |     |
   |   No  -> Skip
   |     |
   +<----+
   |
   v
4. Write Config (atomic)
   |
   v
5. Report Changes
```

## Check Implementation Pattern

Example check implementation:

```go
// pkg/checks/gateway_exposure.go

type GatewayExposureCheck struct{}

func (c *GatewayExposureCheck) ID() string {
    return "V01"
}

func (c *GatewayExposureCheck) Name() string {
    return "Gateway Exposure"
}

func (c *GatewayExposureCheck) Severity() Severity {
    return SeverityCritical
}

func (c *GatewayExposureCheck) Run(ctx *CheckContext) ([]Finding, error) {
    var findings []Finding

    bind := ctx.Config.Gateway.Bind
    if bind == "" {
        bind = "loopback"
    }

    hasAuth := c.hasValidAuth(ctx.Config)
    isExposed := !isLoopback(bind)

    if isExposed && !hasAuth {
        findings = append(findings, Finding{
            CheckID:     c.ID(),
            Severity:    SeverityCritical,
            Title:       "Gateway binds beyond loopback without auth",
            Detail:      fmt.Sprintf("gateway.bind=%q but no auth configured", bind),
            Remediation: "Set gateway.auth (token recommended) or bind to loopback",
            CanAutoFix:  true,
        })
    }

    return findings, nil
}

func (c *GatewayExposureCheck) CanFix() bool {
    return true
}

func (c *GatewayExposureCheck) Fix(ctx *FixContext) error {
    // Default fix: set bind to loopback
    return ctx.SetConfig("gateway.bind", "loopback")
}
```

## Filesystem Checks

Permissions are checked using platform-specific methods:

### POSIX (macOS/Linux)

```go
func inspectPosixPermissions(path string) (*PathPermissions, error) {
    info, err := os.Lstat(path)
    if err != nil {
        return nil, err
    }

    mode := info.Mode().Perm()
    return &PathPermissions{
        Path:          path,
        Mode:          mode,
        IsSymlink:     info.Mode()&os.ModeSymlink != 0,
        WorldReadable: mode&0004 != 0,
        WorldWritable: mode&0002 != 0,
        GroupReadable: mode&0040 != 0,
        GroupWritable: mode&0020 != 0,
    }, nil
}
```

### Windows

```go
func inspectWindowsACL(path string, exec ExecFn) (*PathPermissions, error) {
    // Use icacls to query ACLs
    output, err := exec("icacls", path)
    if err != nil {
        return nil, err
    }
    return parseIcaclsOutput(output)
}
```

## Deep Probe

Optional live connectivity testing:

```go
type DeepProbe struct {
    GatewayURL string
    Auth       *AuthConfig
    TimeoutMs  int
}

func (p *DeepProbe) Probe() (*ProbeResult, error) {
    // 1. Attempt WebSocket connection
    conn, err := p.dialWebSocket()
    if err != nil {
        return &ProbeResult{OK: false, Error: err.Error()}, nil
    }
    defer conn.Close()

    // 2. Send health check
    // 3. Verify auth is required
    // 4. Check for exposed endpoints

    return &ProbeResult{OK: true}, nil
}
```

## Concurrency

Checks run concurrently where safe:

```go
func (s *Scanner) Scan(ctx context.Context) (*ScanReport, error) {
    var wg sync.WaitGroup
    findings := make(chan Finding, 100)

    // Group checks by dependency
    independent := s.getIndependentChecks()
    dependent := s.getDependentChecks()

    // Run independent checks concurrently
    for _, check := range independent {
        wg.Add(1)
        go func(c Check) {
            defer wg.Done()
            results, _ := c.Run(s.checkContext())
            for _, f := range results {
                findings <- f
            }
        }(check)
    }

    // Wait for independent checks
    wg.Wait()

    // Run dependent checks sequentially
    for _, check := range dependent {
        results, _ := check.Run(s.checkContext())
        for _, f := range results {
            findings <- f
        }
    }

    close(findings)
    return s.aggregateFindings(findings)
}
```

## Error Handling

Checks use structured errors:

```go
type CheckError struct {
    CheckID string
    Phase   string
    Err     error
}

func (e *CheckError) Error() string {
    return fmt.Sprintf("%s: %s: %v", e.CheckID, e.Phase, e.Err)
}

// Usage
if err != nil {
    return nil, &CheckError{
        CheckID: c.ID(),
        Phase:   "read_config",
        Err:     err,
    }
}
```

## Testing

### Unit Tests

Each check has corresponding tests:

```go
func TestGatewayExposureCheck(t *testing.T) {
    tests := []struct {
        name     string
        config   *MoltbotConfig
        expected int // number of findings
    }{
        {
            name: "loopback with no auth is ok",
            config: &MoltbotConfig{
                Gateway: GatewayConfig{Bind: "loopback"},
            },
            expected: 0,
        },
        {
            name: "lan bind without auth is critical",
            config: &MoltbotConfig{
                Gateway: GatewayConfig{Bind: "lan"},
            },
            expected: 1,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            check := &GatewayExposureCheck{}
            findings, err := check.Run(&CheckContext{Config: tt.config})
            require.NoError(t, err)
            assert.Len(t, findings, tt.expected)
        })
    }
}
```

### Integration Tests

Full scan tests with real config files:

```go
func TestFullScan(t *testing.T) {
    cfg, err := LoadTestConfig("testdata/insecure.json")
    require.NoError(t, err)

    scanner := NewScanner(cfg, ScanOptions{})
    report, err := scanner.Scan(context.Background())
    require.NoError(t, err)

    assert.Equal(t, 5, report.Summary.Critical)
    assert.Contains(t, report.FindingIDs(), "V01")
}
```

## Extension Points

### Custom Checks

Register custom checks at runtime:

```go
scanner.RegisterCheck(&MyCustomCheck{})
```

### Custom Reporters

Implement the `Reporter` interface:

```go
type SlackReporter struct {
    WebhookURL string
}

func (r *SlackReporter) Report(report *ScanReport, w io.Writer) error {
    // Format for Slack and POST to webhook
}
```

### Hooks

Pre/post scan hooks:

```go
scanner.OnBeforeScan(func(ctx *CheckContext) error {
    // Validate prerequisites
    return nil
})

scanner.OnAfterFix(func(result *FixResult) error {
    // Notify about changes
    return nil
})
```

## Performance Considerations

- **Caching**: Config is parsed once and shared across checks
- **Lazy loading**: Filesystem checks only stat required paths
- **Parallel I/O**: Independent file checks run concurrently
- **Timeout handling**: Deep probes have configurable timeouts
- **Memory**: Findings are streamed to avoid large allocations

## Security Considerations

The hardener itself must be secure:

- **No execution of untrusted code**: Config is parsed, not executed
- **Minimal permissions**: Only reads config and state files
- **Atomic writes**: Config changes are written atomically
- **Backup before modify**: Original config is backed up
- **No network by default**: Deep probe is opt-in
- **Secrets redacted**: Tokens are masked in output
