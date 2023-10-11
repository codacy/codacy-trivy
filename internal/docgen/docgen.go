package docgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
	"golang.org/x/mod/modfile"
)

const toolName string = "trivy"

type DocumentationGenerator interface {
	Generate(destinationDir string) error
}

// New creates a new instance of the documentation generator.
func New() DocumentationGenerator {
	return &documentationGenerator{}
}

type documentationGenerator struct{}

func (g documentationGenerator) Generate(destinationDir string) error {
	trivyRules := trivyRules()

	trivyVersion, err := trivyVersion()
	if err != nil {
		return err
	}

	if err := g.createPatternsFile(trivyRules, *trivyVersion, destinationDir); err != nil {
		return err
	}

	if err := g.createPatternsDescriptionFiles(trivyRules, destinationDir); err != nil {
		return err
	}
	return nil
}

// trivyVersion returns the current version of the trivy library used.
func trivyVersion() (*string, error) {
	goModFilename := "go.mod"
	dependency := "github.com/aquasecurity/trivy"

	goMod, err := os.ReadFile(goModFilename)
	if err != nil {
		return nil, &DocGenError{msg: fmt.Sprintf("Failed to load %s file", goModFilename), w: err}
	}

	file, _ := modfile.Parse(goModFilename, goMod, nil)
	for _, r := range file.Require {
		if r.Mod.Path == dependency {
			version := strings.TrimPrefix(r.Mod.Version, "v")
			return &version, nil
		}
	}
	return nil, &DocGenError{msg: fmt.Sprintf("%s dependency not found in %s file", dependency, goModFilename)}
}

func (g documentationGenerator) createPatternsFile(rules Rules, toolVersion, destinationDir string) error {
	fmt.Println("Creating patterns file...")

	patternsFile := "patterns.json"

	tool := codacy.ToolDefinition{
		Name:     toolName,
		Version:  toolVersion,
		Patterns: rules.toCodacyPattern(),
	}

	toolJSON, err := json.MarshalIndent(tool, "", "  ")
	if err != nil {
		return newFileContentError(patternsFile, err)
	}

	if err := os.WriteFile(path.Join(destinationDir, patternsFile), toolJSON, 0644); err != nil {
		return newFileCreationError(patternsFile, err)
	}
	return nil
}

func (g documentationGenerator) createPatternsDescriptionFiles(rules Rules, destinationDir string) error {
	fmt.Println("Creating description files...")

	patternsDescriptionFolder := "description"
	patternsDescriptionFile := "description.json"

	patternsDescription := rules.toCodacyPatternDescription()

	for _, patternDescription := range patternsDescription {
		fileName := fmt.Sprintf("%s.md", patternDescription.PatternID)
		fileContent := fmt.Sprintf("## %s\n%s", patternDescription.Title, patternDescription.Description)

		if err := os.WriteFile(path.Join(destinationDir, patternsDescriptionFolder, fileName), []byte(fileContent), 0644); err != nil {
			return newFileCreationError(fileName, err)
		}
	}

	descriptionsJSON, err := json.MarshalIndent(patternsDescription, "", "  ")
	if err != nil {
		return newFileContentError(patternsDescriptionFile, err)
	}

	if err := os.WriteFile(path.Join(destinationDir, patternsDescriptionFolder, patternsDescriptionFile), descriptionsJSON, 0644); err != nil {
		return newFileCreationError(patternsDescriptionFile, err)
	}
	return nil
}

func newFileCreationError(fileName string, w error) error {
	return &DocGenError{msg: fmt.Sprintf("Failed to create %s file", fileName), w: w}
}
func newFileContentError(fileName string, w error) error {
	return &DocGenError{msg: fmt.Sprintf("Failed to marshal %s file content", fileName), w: w}
}
