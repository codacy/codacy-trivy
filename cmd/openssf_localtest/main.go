package main

import (
	"fmt"
	"os"
	"path/filepath"

	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/codacy/codacy-trivy/internal/tool"
)

func main() {
	// Source directory containing the test package.json
	// docs/multiple-tests/pattern-malicious/src
	cwd, _ := os.Getwd()
	sourceDir := filepath.Join(cwd, "docs/multiple-tests/pattern-malicious/src")
	target := "javascript/package.json"

	// Construct a minimal Trivy report so the scanner knows the target file
	report := ptypes.Report{
		Results: []ptypes.Result{{
			Target:   target,
			Packages: nil, // force fallback to parse package.json directly
		}},
	}

	// Configure Codacy execution enabling only malicious_packages and limiting to the target file
	files := []string{target}
	patterns := []codacy.Pattern{{ID: "malicious_packages"}}
	exec := codacy.ToolExecution{SourceDir: sourceDir, Files: &files, Patterns: &patterns}

	scanner := tool.NewOpenSSFScanner()
	results := scanner.ScanForMaliciousPackages(report, exec)

	fmt.Printf("Findings: %d\n", len(results))
	for _, r := range results {
		switch v := r.(type) {
		case codacy.Issue:
			fmt.Printf("%s:%d: %s (%s)\n", v.File, v.Line, v.Message, v.PatternID)
		default:
			fmt.Printf("%s: %T\n", r.GetFile(), r)
		}
	}
}
