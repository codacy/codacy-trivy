package main

import (
	"bytes"
	"fmt"
	"os"
	"path"

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
	"github.com/samber/lo"
)

const secretRuleID string = "secret"

func runTrivy(patterns []codacy.Pattern, files []string, sourceDir string) ([]codacy.Issue, error) {
	if secretDetectionEnabled := lo.SomeBy(
		patterns,
		func(p codacy.Pattern) bool {
			return p.PatternID == secretRuleID
		},
	); !secretDetectionEnabled {
		return []codacy.Issue{}, nil
	}

	scanner := secret.NewScanner(&secret.Config{})

	var results []codacy.Issue

	for _, f := range files {
		content, err := os.ReadFile(path.Join(sourceDir, f))
		if err != nil {
			return nil, fmt.Errorf("Error reading file %s from dir %s: %w", f, sourceDir, err)
		}
		content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))
		secrets := scanner.Scan(
			secret.ScanArgs{
				FilePath: f,
				Content:  content,
			},
		)
		for _, result := range secrets.Findings {
			results = append(
				results,
				codacy.Issue{
					File:      f,
					Message:   fmt.Sprintf("Possible hardcoded secret: %s", result.Title),
					PatternID: secretRuleID,
					Line:      result.StartLine,
				},
			)
		}
	}

	return results, nil
}

type TrivyImplementation struct{}

// https://github.com/uber-go/guide/blob/master/style.md#verify-interface-compliance
var _ codacy.ToolImplementation = (*TrivyImplementation)(nil)

func (i TrivyImplementation) Run(tool codacy.Tool, sourceDir string) ([]codacy.Issue, error) {
	// Trivy configuration in the Codacy prodcut does not allow for a configuration file.
	// If the tool itself does not have patterns, then there is something wrong.
	if len(tool.Patterns) == 0 {
		return nil, fmt.Errorf("Error reading configuration: Tool has no patterns and no configuration file.")
	}

	results, err := runTrivy(tool.Patterns, tool.Files, sourceDir)
	if err != nil {
		return nil, fmt.Errorf("Error running Trivy: %w", err)
	}

	return results, nil
}

func main() {
	codacy.StartTool(&TrivyImplementation{})
}
