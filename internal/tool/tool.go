package tool

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	tresult "github.com/aquasecurity/trivy/pkg/result"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/samber/lo"
	"golang.org/x/mod/semver"
)

const (
	ruleIDSecret              string = "secret"
	ruleIDVulnerability       string = "vulnerability"
	ruleIDVulnerabilityMedium string = "vulnerability_medium"
	ruleIDVulnerabilityMinor  string = "vulnerability_minor"

	// See https://aquasecurity.github.io/trivy/v0.54/docs/scanner/vulnerability/#severity-selection
	trivySeverityLow      string = "low"
	trivySeverityMedium   string = "medium"
	trivySeverityHigh     string = "high"
	trivySeverityCritical string = "critical"

	cacheDir string = "/dist/cache/codacy-trivy"
)

// ruleIDsVulnerability contains IDs all rule (or pattern) IDs that find vulnerable dependencies.
var ruleIDsVulnerability = []string{ruleIDVulnerability, ruleIDVulnerabilityMedium, ruleIDVulnerabilityMinor}

// New creates a new instance of Codacy Trivy.
func New() codacyTrivy {
	return codacyTrivy{
		runnerFactory: &defaultRunnerFactory{},
	}
}

type codacyTrivy struct {
	runnerFactory RunnerFactory
}

// https://github.com/uber-go/guide/blob/master/style.md#verify-interface-compliance
var _ codacy.Tool = (*codacyTrivy)(nil)

func (t codacyTrivy) Run(ctx context.Context, toolExecution codacy.ToolExecution) ([]codacy.Result, error) {
	err := validateExecutionConfiguration(toolExecution)
	if err != nil {
		return nil, err
	}
	// The `quiet` field in Trivy configuration is not used by the runner.
	// This is the only way to suppress Trivy logs.
	log.InitLogger(false, true)

	vulnerabilityScanningIssues, err := t.runVulnerabilityScanning(ctx, toolExecution)
	if err != nil {
		return nil, err
	}

	secretScanningIssues := t.runSecretScanning(toolExecution)

	allIssues := append(vulnerabilityScanningIssues, secretScanningIssues...)

	return allIssues, nil
}

func (t codacyTrivy) runVulnerabilityScanning(ctx context.Context, toolExecution codacy.ToolExecution) ([]codacy.Result, error) {
	vulnerabilityScanningEnabled := lo.SomeBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return lo.Contains(ruleIDsVulnerability, p.ID)
	})
	if !vulnerabilityScanningEnabled {
		return []codacy.Result{}, nil
	}

	trivySeverities := getTrivySeveritiesFromPatterns(*toolExecution.Patterns)
	// This should never happen, given that we validate the patterns above. Still, it's a failsafe.
	if len(trivySeverities) == 0 {
		return nil, &ToolError{msg: fmt.Sprintf("Failed to run Codacy Trivy: vulnerability patterns did not produce severities (patterns %v)", *toolExecution.Patterns)}
	}

	// Workaround for detecting vulnerabilities in the Go standard library.
	// Mimics the behavior of govulncheck by replacing the go version directive with a require statement for stdlib. https://go.dev/blog/govulncheck
	// This is only supported by Trivy for Go binaries. https://github.com/aquasecurity/trivy/issues/4133
	toolExecution.SourceDir = patchGoModFilesForStdlib(toolExecution.SourceDir, *toolExecution.Files)

	config := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			// CacheDir needs to be explicitly set and match the directory in the Dockerfile.
			// The cache dir will contain the pre-downloaded vulnerability DBs.
			CacheDir: cacheDir,
		},
		DBOptions: flag.DBOptions{
			// Do not try to update vulnerability DBs.
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			// Only scan libraries not OS packages.
			PkgTypes: []string{ptypes.PkgTypeLibrary},
			// Scan libraries with all possible relationships (direct, indirect, etc).
			PkgRelationships: ftypes.Relationships,
		},
		ReportOptions: flag.ReportOptions{
			// Listing all packages will allow to obtain the line number of a vulnerability.
			ListAllPkgs: true,
		},
		ScanOptions: flag.ScanOptions{
			// Do not try to connect to the internet to download vulnerability DBs, for example.
			OfflineScan: true,
			Scanners:    ptypes.Scanners{ptypes.VulnerabilityScanner},
			// Instead of scanning files individually, scan the whole source directory since it's faster.
			// Then filter issues from files that were not supposed to be analysed.
			Target: toolExecution.SourceDir,
		},
	}

	runner, err := t.runnerFactory.NewRunner(ctx, config)
	if err != nil {
		return nil, err
	}
	defer runner.Close(ctx)

	results, err := runner.ScanFilesystem(ctx, config)
	if err != nil {
		return nil, &ToolError{msg: "Failed to run Codacy Trivy", w: err}
	}

	issues := []codacy.Issue{}
	for _, result := range results.Results {
		// Make a map for faster lookup
		lineNumberByPackageId := map[string]int{}
		for _, pkg := range result.Packages {
			lineNumber := 0
			if len(pkg.Locations) > 0 {
				lineNumber = pkg.Locations[0].StartLine
			}
			lineNumberByPackageId[pkgID(pkg.ID, pkg.Name, pkg.Version)] = lineNumber
		}

		// Ensure Trivy only produces results with severities matching the specified patterns.
		// Due to the way we invoke Trivy, this won't happen by simply setting it in the config.
		if err := tresult.FilterResult(ctx, &result, tresult.IgnoreConfig{}, tresult.FilterOptions{Severities: trivySeverities}); err != nil {
			return nil, &ToolError{msg: "Failed to run Codacy Trivy", w: err}
		}

		for _, vuln := range result.Vulnerabilities {
			ID := pkgID(vuln.PkgID, vuln.PkgName, vuln.InstalledVersion)

			// If the line number is not available, use the fallback.
			if value, ok := lineNumberByPackageId[ID]; !ok || value == 0 {
				lineNumberByPackageId[ID] = fallbackSearchForLineNumber(toolExecution.SourceDir, result.Target, vuln.PkgName)
			}

			// Find the smallest version increment that fixes a vulnerabillity
			fixedVersion := findLeastDisruptiveFixedVersion(vuln)
			fixedVersionMessage := ""
			if len(fixedVersion) > 0 {
				fixedVersionMessage = fmt.Sprintf("(update to %s)", fixedVersion)
			} else {
				fixedVersionMessage = "(no fix available)"
			}

			ruleId, err := getRuleIdFromTrivySeverity(vuln.Severity)
			// This should not be possible since we filter out vulnerabilities with unknown severities. Still, it's a failsafe.
			if err != nil {
				return nil, err
			}

			issues = append(
				issues,
				codacy.Issue{
					File:      result.Target,
					Line:      lineNumberByPackageId[ID],
					Message:   fmt.Sprintf("Insecure dependency %s (%s: %s) %s", ID, vuln.VulnerabilityID, vuln.Title, fixedVersionMessage),
					PatternID: ruleId,
				},
			)
		}

	}

	return mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(issues, *toolExecution.Files)), nil
}

// Running Trivy for secret scanning is not as efficient as running for vulnerability scanning.
// It's much more efficient to run the two scan separately, even though that results in more wrapper code.
func (t codacyTrivy) runSecretScanning(toolExecution codacy.ToolExecution) []codacy.Result {
	secretDetectionEnabled := lo.SomeBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDSecret
	})
	if !secretDetectionEnabled {
		return []codacy.Result{}
	}

	scanner := secret.NewScanner(&secret.Config{})

	results := []codacy.Result{}

	for _, f := range *toolExecution.Files {

		filePath := path.Join(toolExecution.SourceDir, f)
		content, err := os.ReadFile(filePath)

		if err != nil {
			results = append(
				results,
				codacy.FileError{
					File:    f,
					Message: "Failed to read source file",
				},
			)
		}
		content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))

		secrets := scanner.Scan(secret.ScanArgs{FilePath: filePath, Content: content})

		for _, result := range secrets.Findings {
			results = append(
				results,
				codacy.Issue{
					File:      f,
					Message:   fmt.Sprintf("Possible hardcoded secret: %s", result.Title),
					PatternID: ruleIDSecret,
					Line:      result.StartLine,
				},
			)
		}
	}
	return results
}

// validateExecutionConfiguration returns an error if the provided configuration has values that will prevent the tool from running properly.
func validateExecutionConfiguration(toolExecution codacy.ToolExecution) error {
	if toolExecution.Patterns == nil || len(*toolExecution.Patterns) == 0 {
		return &ToolError{msg: "Failed to configure Codacy Trivy: no patterns configured"}
	}

	noSupportedPatterns := lo.NoneBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDSecret || lo.Contains(ruleIDsVulnerability, p.ID)
	})
	if noSupportedPatterns {
		patternIDs := lo.Map(*toolExecution.Patterns, func(p codacy.Pattern, _ int) string {
			return p.ID
		})
		return &ToolError{msg: fmt.Sprintf("Failed to configure Codacy Trivy: configured patterns don't match existing rules (provided %v)", patternIDs)}
	}

	if toolExecution.Files == nil || len(*toolExecution.Files) == 0 {
		// TODO Run for all files in the source dir?
		return &ToolError{msg: "Failed to configure Codacy Trivy: no files to analyse"}
	}

	return nil
}

// getRuleIdFromTrivySeverity converts from Trivy severity to Codacy's rule (or pattern) IDs.
// If there is no match, an error is returned.
func getRuleIdFromTrivySeverity(severity string) (string, error) {
	switch strings.ToLower(severity) {
	case trivySeverityLow:
		return ruleIDVulnerabilityMinor, nil
	case trivySeverityMedium:
		return ruleIDVulnerabilityMedium, nil
	case trivySeverityHigh, trivySeverityCritical:
		return ruleIDVulnerability, nil
	default:
		return "", &ToolError{msg: fmt.Sprintf("Failed to run Codacy Trivy: unexpected Trivy severity %s", severity)}
	}
}

// getTrivySeveritiesFromPatterns converts from Codacy's rule (or pattern) IDs to Trivy severities, for configuring a vulnerability scan.
// If there is no match an empty slice is returned.
func getTrivySeveritiesFromPatterns(patterns []codacy.Pattern) []dbTypes.Severity {
	var trivySeverities []dbTypes.Severity
	for _, pattern := range patterns {
		switch strings.ToLower(pattern.ID) {
		case ruleIDVulnerability:
			trivySeverities = append(trivySeverities, dbTypes.SeverityCritical, dbTypes.SeverityHigh)
		case ruleIDVulnerabilityMedium:
			trivySeverities = append(trivySeverities, dbTypes.SeverityMedium)
		case ruleIDVulnerabilityMinor:
			trivySeverities = append(trivySeverities, dbTypes.SeverityLow)
		}
	}
	return trivySeverities
}

// Results without a line number (0 is the empty value) can't be displayed by Codacy and are mapped to a `codacy.FileError`.
// Furthermore, this function guarantees only one `codacy.FileError` per file.
func mapIssuesWithoutLineNumber(issues []codacy.Issue) []codacy.Result {
	issuesWithLineNumbers := lo.FilterMap(issues, func(issue codacy.Issue, _ int) (codacy.Result, bool) {
		return issue, issue.Line > 0
	})

	fileErrors := lo.FilterMap(issues, func(issue codacy.Issue, _ int) (codacy.Result, bool) {
		return codacy.FileError{
			File:    issue.File,
			Message: "Line numbers not supported",
		}, issue.Line <= 0
	})
	uniqueFileErrors := lo.UniqBy(fileErrors, func(result codacy.Result) string {
		return result.GetFile()
	})

	return append(issuesWithLineNumbers, uniqueFileErrors...)
}

// Trivy analyses the whole source dir, since it's faster than analysing individual files.
// However, some files in the source dir might be marked as ignored in Codacy,
// so we want to filter issues from known files only (i.e. the ones provided as argument in the run command).
func filterIssuesFromKnownFiles(issues []codacy.Issue, knownFiles []string) []codacy.Issue {
	return lo.Filter(issues, func(issue codacy.Issue, _ int) bool {
		return lo.SomeBy(knownFiles, func(file string) bool {
			return issue.File == file
		})
	})
}

// If the line number is not available in the Trivy result, try to find it in the source file.
// Returns 0 if the line number is not found.
func fallbackSearchForLineNumber(sourceDir, fileName, pkgName string) int {
	if pkgName == "" {
		return 0
	}

	filePath := filepath.Join(sourceDir, fileName)
	f, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	line := 1
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), pkgName) {
			return line
		}
		line++
	}

	return 0
}

// Find the smallest version increment that fixes a vulnerabillity, assuming semantic version format.
// Doesn't support package managers that use a different versioning scheme. (like Ruby's `~>`)
// Otherwise, return the original versions list.
func findLeastDisruptiveFixedVersion(vuln ptypes.DetectedVulnerability) string {
	allUpdates := strings.Split(vuln.FixedVersion, ", ")
	possibleUpdates := lo.Filter(allUpdates, func(v string, index int) bool {
		return semver.Compare(fmt.Sprintf("v%s", v), fmt.Sprintf("v%s", vuln.InstalledVersion)) > 0
	})
	semver.Sort(possibleUpdates)

	if len(possibleUpdates) > 0 {
		return possibleUpdates[0]
	}
	return vuln.FixedVersion
}

func pkgID(id, name, version string) string {
	if id != "" {
		return id
	}
	return fmt.Sprintf("%s@%s", name, version)
}
