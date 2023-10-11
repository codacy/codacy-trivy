package tool

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

type CodacyTrivy struct{}

// https://github.com/uber-go/guide/blob/master/style.md#verify-interface-compliance
var _ codacy.ToolImplementation = (*CodacyTrivy)(nil)

func (t CodacyTrivy) Run(tool codacy.Tool, sourceDir string) ([]codacy.Issue, error) {
	if len(tool.Patterns) == 0 {
		// TODO Use configuration from source code or default configuration file.
		return []codacy.Issue{}, nil
	}

	return run(tool.Patterns, tool.Files, sourceDir)
}

func run(patterns []codacy.Pattern, files []string, sourceDir string) ([]codacy.Issue, error) {
	var secretDetectionEnabled = lo.SomeBy(patterns, func(p codacy.Pattern) bool {
		return p.PatternID == secretRuleID
	})
	if !secretDetectionEnabled {
		return []codacy.Issue{}, nil
	}

	scanner := secret.NewScanner(&secret.Config{})

	results := []codacy.Issue{}

	for _, f := range files {
		filePath := path.Join(sourceDir, f)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, ToolError{msg: fmt.Sprintf("Failed to read source file %s", f), w: err}
		}
		content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))

		secrets := scanner.Scan(secret.ScanArgs{FilePath: filePath, Content: content})
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
