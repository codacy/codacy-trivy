package tool

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	tresult "github.com/aquasecurity/trivy/pkg/result"
	tcdx "github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/codacy/codacy-trivy/internal"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/mod/semver"
)

const (
	ruleIDSecret              string = "secret"
	ruleIDVulnerability       string = "vulnerability"
	ruleIDVulnerabilityMedium string = "vulnerability_medium"
	ruleIDVulnerabilityMinor  string = "vulnerability_minor"

	// See https://aquasecurity.github.io/trivy/v0.59/docs/scanner/vulnerability/#severity-selection
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

	report, err := t.runBaseScan(ctx, toolExecution.SourceDir)
	if err != nil {
		return nil, err
	}

	sbom, err := t.getSBOM(ctx, report)
	if err != nil {
		return nil, err
	}

	vulnerabilityScanningIssues, err := t.getVulnerabilities(ctx, report, toolExecution)
	if err != nil {
		return nil, err
	}

	secretScanningIssues := t.runSecretScanning(toolExecution)

	allIssues := append(vulnerabilityScanningIssues, secretScanningIssues...)
	allIssues = append(allIssues, sbom)

	return allIssues, nil
}

// runBaseScan will run a vulnerability scan that produces a report to be used for SBOM generation or for vulnerability issues.
func (t codacyTrivy) runBaseScan(ctx context.Context, sourceDir string) (ptypes.Report, error) {
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
			Target: sourceDir,
			// Detects more vulnerabilities, potentially including some that might be false positives.
			// This is REQUIRED for detecting vulnerabilites in go standard library.
			DetectionPriority: ftypes.PriorityComprehensive,
		},
		// Make Trivy automatically select a severity for a vulnerability, from its many sources.
		// This is used by default when calling Trivy from the command line but given our Trivy usage, we need to make it explicit.
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbTypes.SourceID{dbTypes.SourceID("auto")},
		},
	}

	// Right now we only support vulnerability scans for file system targets.
	runner, err := t.runnerFactory.NewRunner(ctx, config, artifact.TargetFilesystem)
	if err != nil {
		return ptypes.Report{}, err
	}
	defer runner.Close(ctx)

	results, err := runner.ScanFilesystem(ctx, config)
	if err != nil {
		return ptypes.Report{}, &ToolError{msg: "Failed to run Codacy Trivy", w: err}
	}

	return results, nil
}

// getVulnerabilties obtains the vulnerable dependency issues from `report` respecting the `toolExecution` configuration,
// with regards to patterns enabled, files to scan and line numbers. See [mapIssuesWithoutLineNumber] and [filterIssuesFromKnownFiles].
//
// If no vulnerability patterns are configured, this method returns immediately with empty results.
func (t codacyTrivy) getVulnerabilities(ctx context.Context, report ptypes.Report, toolExecution codacy.ToolExecution) ([]codacy.Result, error) {
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

	issues := []codacy.Issue{}
	for _, result := range report.Results {
		// Make a map for faster lookup
		lineNumberByPurl := map[string]int{}
		for _, pkg := range result.Packages {
			lineNumber := 0
			if len(pkg.Locations) > 0 {
				lineNumber = pkg.Locations[0].StartLine
			}
			lineNumberByPurl[pkg.Identifier.PURL.ToString()] = lineNumber
		}

		// Ensure Trivy only produces results with severities matching the specified patterns.
		// Due to the way we invoke Trivy, this won't happen by simply setting it in the config.
		if err := tresult.FilterResult(ctx, &result, tresult.IgnoreConfig{}, tresult.FilterOptions{Severities: trivySeverities}); err != nil {
			return nil, &ToolError{msg: "Failed to run Codacy Trivy", w: err}
		}

		for _, vuln := range result.Vulnerabilities {
			purl := vuln.PkgIdentifier.PURL.ToString()
			// If the line number is not available, use the fallback.
			if value, ok := lineNumberByPurl[purl]; !ok || value == 0 {
				lineNumberByPurl[purl] = fallbackSearchForLineNumber(toolExecution.SourceDir, result.Target, vuln.PkgName)
			}

			// Find the smallest version increment that fixes a vulnerabillity
			fixedVersion := findLeastDisruptiveFixedVersion(vuln)
			fixedVersionMessage := ""
			if len(fixedVersion) > 0 {
				fixedVersionMessage = fmt.Sprintf("(update to %s)", fixedVersion)
			} else {
				fixedVersionMessage = "(no fix available)"
			}

			ruleID, err := getRuleIDFromTrivySeverity(vuln.Severity)
			// This should not be possible since we filter out vulnerabilities with unknown severities. Still, it's a failsafe.
			if err != nil {
				return nil, err
			}

			issues = append(
				issues,
				codacy.Issue{
					File:      result.Target,
					Line:      lineNumberByPurl[purl],
					Message:   fmt.Sprintf("Insecure dependency %s (%s: %s) %s", purlPrettyPrint(*vuln.PkgIdentifier.PURL), vuln.VulnerabilityID, vuln.Title, fixedVersionMessage),
					PatternID: ruleID,
					SourceID:  vuln.VulnerabilityID,
				},
			)
		}

	}

	return mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(issues, *toolExecution.Files)), nil
}

// getSBOM produces a SBOM result from `report`.
func (t codacyTrivy) getSBOM(ctx context.Context, report ptypes.Report) (codacy.SBOM, error) {
	marshaler := tcdx.NewMarshaler(internal.TrivyVersion())
	bom, err := marshaler.MarshalReport(ctx, report)
	if err != nil {
		return codacy.SBOM{}, &ToolError{msg: "Failed to run Codacy Trivy", w: err}
	}

	unencodeComponents(bom)
	return codacy.SBOM{BOM: *bom}, nil
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

	scanner := secret.NewScanner(nil)

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
					SourceID:  result.RuleID,
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

	return nil
}

// getRuleIDFromTrivySeverity converts from Trivy severity to Codacy's rule (or pattern) IDs.
// If there is no match, an error is returned.
func getRuleIDFromTrivySeverity(severity string) (string, error) {
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
	goDirectiveLine := 0
	isGoModStdLib := strings.HasSuffix(fileName, "go.mod") && pkgName == "stdlib"
	for scanner.Scan() {
		lineText := strings.TrimSpace(scanner.Text())

		// Issues in go standard library are reported in package `stdlib` which does not literally exist in go.mod.
		//
		// Trivy uses `stdlib` to refer to the standard library defined in `toolchain` or `go` directives in go.mod.
		// Trivy supposedly uses the minimum version between `toolchain` and `go` directives (see https://trivy.dev/v0.59/docs/coverage/language/golang/#gomod-stdlib)
		// but in reality it ALWAYS uses the version defined in `toolchain` when it exists.
		if isGoModStdLib {
			// If there is a `toolchain` directive use its line.
			if strings.HasPrefix(lineText, "toolchain ") {
				return line
			}
			// Only use the `go` directive line after scanning the whole file and there is no `toolchain` directive
			if strings.HasPrefix(lineText, "go ") {
				goDirectiveLine = line
			}
		} else if strings.Contains(lineText, pkgName) {
			return line
		}
		line++
	}

	return goDirectiveLine
}

// Find the smallest version increment that fixes a vulnerabillity, assuming semantic version format.
// Doesn't support package managers that use a different versioning scheme. (like Ruby's `~>`)
// Otherwise, return the original versions list.
//
// The semver library we're using requires a `v` prefix for the version.
// Usually, Trivy prefixes `InstalledVersion` but not `FixedVersion`.
// For safety, we sanitize both values, by removing and adding a `v` prefix.
func findLeastDisruptiveFixedVersion(vuln ptypes.DetectedVulnerability) string {
	sanitizedInstalledVersion := fmt.Sprintf("v%s", strings.TrimPrefix(vuln.InstalledVersion, "v"))

	allUpdates := strings.Split(vuln.FixedVersion, ", ")
	possibleUpdates := lo.Filter(allUpdates, func(v string, index int) bool {
		sanitizedPossibleUpdateVersion := fmt.Sprintf("v%s", strings.TrimPrefix(v, "v"))
		return semver.Compare(sanitizedPossibleUpdateVersion, sanitizedInstalledVersion) > 0
	})
	semver.Sort(possibleUpdates)

	if len(possibleUpdates) > 0 {
		return possibleUpdates[0]
	}
	return vuln.FixedVersion
}

// unencodeComponents decodes URL-encoded fields (`PackageURL`, `BOMRef`) in components and dependencies
// to help downstream consumers of the SBOM file.
//
// This function mutates the provided BOM.
func unencodeComponents(bom *cdx.BOM) {
	components := *bom.Components
	for i, component := range components {
		if purl, err := url.PathUnescape(component.PackageURL); err == nil {
			components[i].PackageURL = purl
		}
		if bomRef, err := url.PathUnescape(component.BOMRef); err == nil {
			components[i].BOMRef = bomRef
		}
	}

	dependencies := *bom.Dependencies
	for i, dependency := range dependencies {
		if ref, err := url.PathUnescape(dependency.Ref); err == nil {
			dependencies[i].Ref = ref
		}

		dDependencies := *dependency.Dependencies
		for j, dDependency := range dDependencies {
			if d, err := url.PathUnescape(dDependency); err == nil {
				dDependencies[j] = d
			}
		}
	}
}

// Remove the pkg: prefix and url-decode the PURL for display purposes.
func purlPrettyPrint(purl packageurl.PackageURL) string {
	purlStripPkg := strings.TrimPrefix(purl.ToString(), "pkg:")
	if ppp, err := url.PathUnescape(purlStripPkg); err == nil {
		return ppp
	}
	return purlStripPkg
}
