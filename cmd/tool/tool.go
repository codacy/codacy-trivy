package main

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
)

const (
	ruleIDSecret        string = "secret"
	ruleIDVulnerability string = "vulnerability"

	cacheDir string = "/dist/cache/codacy-trivy"
)

type CodacyTrivy struct{}

// https://github.com/uber-go/guide/blob/master/style.md#verify-interface-compliance
var _ codacy.ToolImplementation = (*CodacyTrivy)(nil)

func (t CodacyTrivy) Run(tool codacy.Tool, sourceDir string) ([]codacy.Issue, error) {
	if len(tool.Patterns) == 0 {
		// TODO Use configuration from source code or default configuration file.
		return []codacy.Issue{}, nil
	}

	config, err := newConfiguration(tool.Patterns, sourceDir)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	return run(ctx, *config)
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
		return nil, ToolError{msg: "Failed to configure Codacy Trivy: no pattern matches existing rules"}
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
			Target: sourceDir,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			// Only scan libraries not OS packages.
			VulnType: []types.VulnType{types.VulnTypeLibrary},
		},
	}, nil
}

func run(ctx context.Context, config flag.Options) ([]codacy.Issue, error) {
	runner, err := artifact.NewRunner(ctx, config)
	if err != nil {
		return nil, ToolError{msg: "Failed to initialize Codacy Trivy", w: err}
	}
	defer runner.Close(ctx)

	results, err := runner.ScanFilesystem(ctx, config)
	if err != nil {
		return nil, ToolError{msg: "Failed to run Codacy Trivy", w: err}
	}

	issues := []codacy.Issue{}
	for _, result := range results.Results {
		// Make a package map for faster lookup
		packagesWithLineNumberById := map[string]ftypes.Package{}
		for _, pkg := range result.Packages {
			// Only add packages that have a line number
			if len(pkg.Locations) > 0 {
				packagesWithLineNumberById[pkg.ID] = pkg
			}
		}

		// Vulnerability scanning results
		for _, vuln := range result.Vulnerabilities {
			// Only create issues that have an associated line number
			pkg, pkgHasLineNumber := packagesWithLineNumberById[vuln.PkgID]
			if pkgHasLineNumber {
				issues = append(
					issues,
					codacy.Issue{
						File:      result.Target,
						Line:      pkg.Locations[0].StartLine, // Safe to access index 0 due to map construction above.
						Message:   fmt.Sprintf("Insecure dependency %s (%s: %s) (update to %s)", vuln.PkgID, vuln.VulnerabilityID, vuln.Title, vuln.FixedVersion),
						PatternID: ruleIDVulnerability,
					},
				)
			}
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
