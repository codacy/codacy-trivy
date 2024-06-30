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

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	types "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/samber/lo"
	"golang.org/x/mod/semver"
)

const (
	ruleIDSecret        string = "secret"
	ruleIDVulnerability string = "vulnerability"

	cacheDir string = "/dist/cache/codacy-trivy"
)

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
	if toolExecution.Patterns == nil || len(*toolExecution.Patterns) == 0 {
		// TODO Use configuration from the tool configuration file or the default rules from the tool's definition (in that order).
		return []codacy.Result{}, nil
	}

	if toolExecution.Files == nil || len(*toolExecution.Files) == 0 {
		// TODO Run for all files in the source dir?
		return []codacy.Result{}, nil
	}

	err := newConfiguration(*toolExecution.Patterns)
	if err != nil {
		return nil, err
	}

	vulnerabilityScanningIssues, err := t.runVulnerabilityScanning(ctx, toolExecution)
	if err != nil {
		return nil, err
	}

	secretScanningIssues, err := t.runSecretScanning(*toolExecution.Patterns, toolExecution.Files, toolExecution.SourceDir)
	if err != nil {
		return nil, err
	}

	allIssues := append(vulnerabilityScanningIssues, secretScanningIssues...)

	return allIssues, nil
}

func (t codacyTrivy) runVulnerabilityScanning(ctx context.Context, toolExecution codacy.ToolExecution) ([]codacy.Result, error) {
	vulnerabilityScanningEnabled := lo.SomeBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDVulnerability
	})
	if !vulnerabilityScanningEnabled {
		return []codacy.Result{}, nil
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
		ReportOptions: flag.ReportOptions{
			// Listing all packages will allow to obtain the line number of a vulnerability.
			ListAllPkgs: true,
		},
		ScanOptions: flag.ScanOptions{
			// Do not try to connect to the internet to download vulnerability DBs, for example.
			OfflineScan: true,
			Scanners:    types.Scanners{types.VulnerabilityScanner},
			// Instead of scanning files individually, scan the whole source directory since it's faster.
			// Then filter issues from files that were not supposed to be analysed.
			Target: toolExecution.SourceDir,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			// Only scan libraries not OS packages.
			VulnType: []types.VulnType{types.VulnTypeLibrary},
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

		for _, vuln := range result.Vulnerabilities {
			ID := pkgID(vuln.PkgID, vuln.PkgName, vuln.InstalledVersion)

			// If the line number is not available, try to find it in the map.
			if value, ok := lineNumberByPackageId[ID]; !ok || value == 0 {
				lineNumberByPackageId[ID], _ = fallbackSearchForLineNumber(toolExecution.SourceDir, result.Target, vuln.PkgName)
			}

			// find the smallest version increment that fixes a vulnerabillity
			fixedVersion := findLeastDisruptiveFixedVersion(vuln)
			fixedVersionMessage := ""
			if len(fixedVersion) > 0 {
				fixedVersionMessage = fmt.Sprintf("(update to %s)", fixedVersion)
			} else {
				fixedVersionMessage = "(no fix available)"
			}

			issues = append(
				issues,
				codacy.Issue{
					File:      result.Target,
					Line:      lineNumberByPackageId[ID],
					Message:   fmt.Sprintf("Insecure dependency %s (%s: %s) %s", ID, vuln.VulnerabilityID, vuln.Title, fixedVersionMessage),
					PatternID: ruleIDVulnerability,
				},
			)
		}

	}

	return mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(issues, *toolExecution.Files)), nil
}

func newConfiguration(patterns []codacy.Pattern) error {
	if len(patterns) == 0 {
		return &ToolError{msg: "Failed to configure Codacy Trivy: no patterns configured"}
	}

	noSupportedPatterns := lo.NoneBy(patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDSecret || p.ID == ruleIDVulnerability
	})

	if noSupportedPatterns {
		return &ToolError{msg: "Failed to configure Codacy Trivy: provided patterns don't match existing rules"}
	}

	// The `quiet` field in global options is not used by the runner.
	// This is the only way to suppress Trivy logs.
	log.InitLogger(false, true)

	return nil
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
func fallbackSearchForLineNumber(sourceDir, fileName, pkgName string) (int, error) {
	filePath := filepath.Join(sourceDir, fileName)
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	line := 1

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), pkgName) {
			return line, nil
		}
		line++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, nil
}

// Find the smallest version increment that fixes a vulnerabillity, assuming semantic version format.
// Doesn't support package managers that use a different versioning scheme. (like Ruby's `~>`)
// Otherwise, return the original versions list.
func findLeastDisruptiveFixedVersion(vuln types.DetectedVulnerability) string {
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

// Running Trivy for secret scanning is not as efficient as running for vulnerability scanning.
// It's much more efficient to run the two scan separately, even though that results in more wrapper code.
func (t codacyTrivy) runSecretScanning(patterns []codacy.Pattern, files *[]string, sourceDir string) ([]codacy.Result, error) {
	secretDetectionEnabled := lo.SomeBy(patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDSecret
	})
	if !secretDetectionEnabled {
		return []codacy.Result{}, nil
	}

	scanner := secret.NewScanner(&secret.Config{})

	results := []codacy.Result{}

	for _, f := range *files {

		filePath := path.Join(sourceDir, f)
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
	return results, nil
}
