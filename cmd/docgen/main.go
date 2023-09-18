package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
	"golang.org/x/mod/modfile"
)

type RuleDefinition struct {
	ID          string
	Title       string
	Description string
	Level       string
	Category    string
	SubCategory string
	Enabled     bool
}

const toolName string = "trivy"

var docFolder string

func main() {
	flag.StringVar(&docFolder, "docFolder", "docs", "Tool documentation folder")
	flag.Parse()
	os.Exit(run())
}

func run() int {
	rulesList := listTrivyRules()

	codacyPatterns := toCodacyPatterns(rulesList)
	codacyPatternsDescription := toCodacyPatternsDescription(rulesList)

	version, err := trivyVersion()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	err = createPatternsJSONFile(codacyPatterns, version)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	err = createDescriptionFiles(codacyPatternsDescription)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	return 0
}

func trivyVersion() (string, error) {
	goModFilename := "go.mod"
	dependency := "github.com/aquasecurity/trivy"

	goMod, err := os.ReadFile(goModFilename)
	if err != nil {
		return "", err
	}

	file, _ := modfile.Parse(goModFilename, goMod, nil)
	for _, r := range file.Require {
		if r.Mod.Path == dependency {
			return strings.TrimPrefix(r.Mod.Version, "v"), nil
		}
	}
	return "", fmt.Errorf("%s dependency not found", goModFilename)
}

func listTrivyRules() []RuleDefinition {
	return []RuleDefinition{
		{
			ID:          "secret",
			Title:       "Secret detection",
			Description: "Detects secrets that should not be committed to a repository or otherwise disclosed, such as secret keys, passwords, and authentication tokens from multiple products.",
			Level:       "Error",
			Category:    "Security",
			SubCategory: "Cryptography",
			Enabled:     true,
		},
	}
}

func toCodacyPatterns(rules []RuleDefinition) []codacy.Pattern {
	codacyPatterns := []codacy.Pattern{}

	for _, rule := range rules {
		codacyPatterns = append(
			codacyPatterns,
			codacy.Pattern{
				PatternID:   rule.ID,
				Category:    rule.Category,
				Level:       rule.Level,
				SubCategory: rule.SubCategory,
				Enabled:     rule.Enabled,
			},
		)
	}
	return codacyPatterns
}

func patternExtendedDescription(title string, description string) string {
	return fmt.Sprintf("## %s\n%s", title, description)
}

func toCodacyPatternsDescription(rules []RuleDefinition) []codacy.PatternDescription {
	codacyPatternsDescription := []codacy.PatternDescription{}

	for _, rule := range rules {
		codacyPatternsDescription = append(
			codacyPatternsDescription,
			codacy.PatternDescription{
				PatternID:   rule.ID,
				Description: rule.Description,
				Title:       rule.Title,
			},
		)
	}

	return codacyPatternsDescription
}

func createPatternsJSONFile(patterns []codacy.Pattern, toolVersion string) error {
	fmt.Println("Creating patterns.json file...")

	tool := codacy.ToolDefinition{
		Name:     toolName,
		Version:  toolVersion,
		Patterns: patterns,
	}

	toolAsJSON, err := json.MarshalIndent(tool, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path.Join(docFolder, "patterns.json"), toolAsJSON, 0644)
}

func createDescriptionFiles(patternsDescriptionsList []codacy.PatternDescription) error {
	fmt.Println("Creating description files...")

	for _, pattern := range patternsDescriptionsList {

		err := os.WriteFile(
			path.Join(
				docFolder,
				"description",
				pattern.PatternID+".md",
			),
			[]byte(patternExtendedDescription(pattern.Title, pattern.Description)),
			0644,
		)
		if err != nil {
			return err
		}
	}

	descriptionsJSON, err := json.MarshalIndent(patternsDescriptionsList, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(
		path.Join(docFolder, "description", "description.json"),
		descriptionsJSON,
		0644,
	)
}
