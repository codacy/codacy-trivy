package tool

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
	"github.com/samber/lo"
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
var _ codacy.ToolImplementation = (*codacyTrivy)(nil)

func (t codacyTrivy) Run(tool codacy.Tool, sourceDir string) ([]codacy.Issue, error) {
	if len(tool.Patterns) == 0 {
		// TODO Use configuration from source code or default configuration file.
		return []codacy.Issue{}, nil
	}

	config, err := newConfiguration(tool.Patterns, sourceDir)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	issues, err := t.run(ctx, *config)
	if err != nil {
		return nil, err
	}

	// Filter only valid results
	return filterIssuesWithLineNumber(filterIssuesFromKnownFiles(issues, tool.Files)), nil
}

func (t codacyTrivy) run(ctx context.Context, config flag.Options) ([]codacy.Issue, error) {
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
			lineNumberByPackageId[pkg.ID] = lineNumber
		}

		// Vulnerability scanning results
		for _, vuln := range result.Vulnerabilities {
			issues = append(
				issues,
				codacy.Issue{
					File:      result.Target,
					Line:      lineNumberByPackageId[vuln.PkgID],
					Message:   fmt.Sprintf("Insecure dependency %s (%s: %s) (update to %s)", vuln.PkgID, vuln.VulnerabilityID, vuln.Title, vuln.FixedVersion),
					PatternID: ruleIDVulnerability,
				},
			)
		}

		// Secret scanning results
		for _, secret := range result.Secrets {
			issues = append(
				issues,
				codacy.Issue{
					File:      result.Target,
					Line:      secret.StartLine,
					Message:   fmt.Sprintf("Possible hardcoded secret: %s", secret.Title),
					PatternID: ruleIDSecret,
				},
			)
		}
	}
	return issues, nil
}

func newConfiguration(patterns []codacy.Pattern, sourceDir string) (*flag.Options, error) {
	scanners := types.Scanners{}
	for _, pattern := range patterns {
		switch pattern.PatternID {
		case ruleIDSecret:
			scanners = append(scanners, types.SecretScanner)
		case ruleIDVulnerability:
			scanners = append(scanners, types.VulnerabilityScanner)
		}
	}

	if len(scanners) == 0 {
		return nil, &ToolError{msg: "Failed to configure Codacy Trivy: provided patterns don't match existing rules"}
	}

	// The `quiet` field in global options is not used by the runner.
	// This is the only way to suppress Trivy logs.
	log.InitLogger(false, true)

	return &flag.Options{
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
			Scanners:    scanners,
			// Instead of scanning files individually, scan the whole source directory since it's faster.
			// Then filter issues from files that were not supposed to be analysed.
			Target: sourceDir,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			// Only scan libraries not OS packages.
			VulnType: []types.VulnType{types.VulnTypeLibrary},
		},
	}, nil
}

// Issues without a line number (0 is the empty value) can't be displayed by Codacy and should be ignored.
func filterIssuesWithLineNumber(issues []codacy.Issue) []codacy.Issue {
	return lo.Filter(issues, func(issue codacy.Issue, _ int) bool {
		return issue.Line > 0
	})
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
