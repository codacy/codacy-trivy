package tool

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/samber/lo"
)

const (
	daysPerMonth  = 30
	daysSixMonths = 180
)

// EOLRunner runs an EOL scan on an SBOM file and returns matches.
// Production implementation execs the xeol CLI; tests use a mock.
type EOLRunner interface {
	Run(sbomPath string) ([]eolMatch, error)
}

// eolMatch represents one EOL finding from xeol (package + cycle EOL date).
type eolMatch struct {
	PURL     string // package URL for matching to report
	Name     string
	Version  string
	EolDate  string // date string e.g. "2025-06-01"
	CycleID  string // optional, for message
}

// xeolJSON is the structure we parse from xeol CLI -o json.
// See docs/xeol-api-verification.md; exact keys may vary by xeol version.
type xeolJSON struct {
	Matches []xeolMatchJSON `json:"matches"`
}

type xeolMatchJSON struct {
	Package xeolPackageJSON `json:"package"`
	Cycle   xeolCycleJSON   `json:"cycle"`
}

type xeolPackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type xeolCycleJSON struct {
	Eol          string `json:"eol"`
	ReleaseCycle string `json:"release_cycle,omitempty"`
}

// EOLScanner scans for end-of-life packages using an EOLRunner (e.g. xeol CLI).
type EOLScanner struct {
	runner EOLRunner
}

// NewEOLScanner creates an EOL scanner that uses the given runner.
func NewEOLScanner(runner EOLRunner) *EOLScanner {
	return &EOLScanner{runner: runner}
}

// Scan runs the EOL scan and returns Codacy results.
// If no EOL pattern is enabled, returns empty. Uses report to resolve file/line from PURL.
func (s *EOLScanner) Scan(report ptypes.Report, toolExecution codacy.ToolExecution, bom *cdx.BOM) []codacy.Result {
	eolEnabled := lo.SomeBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return lo.Contains(ruleIDsEOL, p.ID)
	})
	if !eolEnabled {
		return []codacy.Result{}
	}

	if bom == nil || bom.Components == nil {
		return []codacy.Result{}
	}

	tmpDir, err := os.MkdirTemp("", "codacy-trivy-sbom-")
	if err != nil {
		return []codacy.Result{codacy.FileError{File: "", Message: "Failed to create temp dir for EOL scan"}}
	}
	defer os.RemoveAll(tmpDir)

	sbomPath := filepath.Join(tmpDir, "sbom.json")
	f, err := os.Create(sbomPath)
	if err != nil {
		return []codacy.Result{codacy.FileError{File: "", Message: "Failed to write SBOM for EOL scan"}}
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bom); err != nil {
		f.Close()
		return []codacy.Result{codacy.FileError{File: "", Message: "Failed to encode SBOM for EOL scan"}}
	}
	if err := f.Close(); err != nil {
		return []codacy.Result{codacy.FileError{File: "", Message: "Failed to close SBOM file"}}
	}

	matches, err := s.runner.Run(sbomPath)
	if err != nil {
		return []codacy.Result{codacy.FileError{File: "", Message: fmt.Sprintf("EOL scan failed: %v", err)}}
	}

	purlToLocation := buildPURLToLocation(report)
	var issues []codacy.Issue
	for _, m := range matches {
		ruleID, err := severityFromEolDate(m.EolDate)
		if err != nil {
			continue
		}
		loc, ok := purlToLocation[m.PURL]
		if !ok {
			// Try by name+version in case PURL format differs
			loc, ok = findLocationByPackage(report, m.Name, m.Version)
			if !ok {
				continue
			}
		}
		line := loc.line
		if line == 0 {
			line = fallbackSearchForLineNumber(toolExecution.SourceDir, loc.target, m.Name)
		}
		msg := fmt.Sprintf("End-of-life package %s@%s (EOL %s)", m.Name, m.Version, m.EolDate)
		if m.CycleID != "" {
			msg = fmt.Sprintf("%s [%s]", msg, m.CycleID)
		}
		issues = append(issues, codacy.Issue{
			File:      loc.target,
			Line:      line,
			Message:   msg,
			PatternID: ruleID,
			SourceID:  m.EolDate,
		})
	}

	return mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(issues, *toolExecution.Files))
}

type pkgLocation struct {
	target string
	line   int
}

func buildPURLToLocation(report ptypes.Report) map[string]pkgLocation {
	out := make(map[string]pkgLocation)
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			if pkg.Identifier.PURL == nil {
				continue
			}
			purlStr := pkg.Identifier.PURL.ToString()
			line := 0
			if len(pkg.Locations) > 0 {
				line = pkg.Locations[0].StartLine
			}
			out[purlStr] = pkgLocation{target: result.Target, line: line}
		}
	}
	return out
}

func findLocationByPackage(report ptypes.Report, name, version string) (pkgLocation, bool) {
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			if pkg.Name == name && pkg.Version == version {
				line := 0
				if len(pkg.Locations) > 0 {
					line = pkg.Locations[0].StartLine
				}
				return pkgLocation{target: result.Target, line: line}, true
			}
		}
	}
	return pkgLocation{}, false
}

// severityFromEolDate maps EOL date to Codacy rule ID.
// Now obsolete -> critical; within 1 month -> high; within 6 months -> medium; else -> minor.
func severityFromEolDate(eolDate string) (string, error) {
	if eolDate == "" {
		return "", fmt.Errorf("empty EOL date")
	}
	t, err := time.Parse("2006-01-02", eolDate)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	// Use start of today for consistent day boundary
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	eolMidnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	daysUntil := int(eolMidnight.Sub(today).Hours() / 24)

	switch {
	case daysUntil <= 0:
		return ruleIDEOLCritical, nil
	case daysUntil <= daysPerMonth:
		return ruleIDEOLHigh, nil
	case daysUntil <= daysSixMonths:
		return ruleIDEOLMedium, nil
	default:
		return ruleIDEOLMinor, nil
	}
}

// XeolCLIRunner runs the xeol CLI on an SBOM path.
type XeolCLIRunner struct {
	ExecPath string   // path to xeol binary; empty means "xeol"
	Env      []string // optional env (e.g. XEOL_DB_CACHE_DIR, XEOL_DB_AUTO_UPDATE=false)
}

// Run executes xeol sbom:<path> -o json --lookahead 365d and parses matches.
func (r *XeolCLIRunner) Run(sbomPath string) ([]eolMatch, error) {
	return runXeolCLI(r.ExecPath, sbomPath, r.Env)
}

// runXeolCLI is the actual CLI invocation (testable with exec).
var runXeolCLI = func(execPath, sbomPath string, env []string) ([]eolMatch, error) {
	return runXeolCLIImpl(execPath, sbomPath, env)
}

func runXeolCLIImpl(execPath, sbomPath string, env []string) ([]eolMatch, error) {
	if execPath == "" {
		execPath = "xeol"
	}
	cmd, stdout, stderr, err := runCommand(execPath, env, "sbom:"+sbomPath, "-o", "json", "--lookahead", "365d")
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	defer stderr.Close()

	var out xeolJSON
	if err := json.NewDecoder(stdout).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode xeol json: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("xeol exit: %w", err)
	}

	matches := make([]eolMatch, 0, len(out.Matches))
	for _, m := range out.Matches {
		purl := m.Package.PURL
		if purl == "" {
			purl = "pkg:generic/" + m.Package.Name + "@" + m.Package.Version
		}
		matches = append(matches, eolMatch{
			PURL:    purl,
			Name:    m.Package.Name,
			Version: m.Package.Version,
			EolDate: m.Cycle.Eol,
			CycleID: m.Cycle.ReleaseCycle,
		})
	}
	return matches, nil
}

// runCommand starts the command and returns stdout/stderr pipes. Caller must call cmd.Wait() and close pipes.
func runCommand(execPath string, env []string, args ...string) (*exec.Cmd, io.ReadCloser, io.ReadCloser, error) {
	cmd := exec.Command(execPath, args...)
	if len(env) > 0 {
		cmd.Env = env
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdout.Close()
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return nil, nil, nil, err
	}
	return cmd, stdout, stderr, nil
}