package docgen

import codacy "github.com/codacy/codacy-engine-golang-seed/v6"

// Rule represents a static code analysis rule that an execution of `codacy-trivy` can trigger.
type Rule struct {
	ID          string
	Title       string
	Description string
	Level       string
	Category    string
	SubCategory string
	ScanType    string
	Enabled     bool
}

func (r Rule) toCodacyPattern() codacy.Pattern {
	return codacy.Pattern{
		ID:          r.ID,
		Category:    r.Category,
		Level:       r.Level,
		SubCategory: r.SubCategory,
		ScanType:    r.ScanType,
		Enabled:     r.Enabled,
	}
}

func (r Rule) toCodacyPatternDescription() codacy.PatternDescription {
	return codacy.PatternDescription{
		PatternID:   r.ID,
		Description: r.Description,
		Title:       r.Title,
	}
}

type Rules []Rule

func (rs Rules) toCodacyPattern() *[]codacy.Pattern {
	codacyPatterns := make([]codacy.Pattern, len(rs))

	for i, r := range rs {
		codacyPatterns[i] = r.toCodacyPattern()
	}
	return &codacyPatterns
}
func (rs Rules) toCodacyPatternDescription() []codacy.PatternDescription {
	codacyPatternsDescription := make([]codacy.PatternDescription, len(rs))

	for i, r := range rs {
		codacyPatternsDescription[i] = r.toCodacyPatternDescription()
	}
	return codacyPatternsDescription
}

// trivyRules returns all `codacy-trivy` Rules.
func trivyRules() Rules {
	return Rules{
		{
			ID:          "secret",
			Title:       "Secret detection",
			Description: "Detects secrets that should not be committed to a repository or otherwise disclosed, such as secret keys, passwords, and authentication tokens from multiple products.",
			Level:       "Error",
			Category:    "Security",
			SubCategory: "Cryptography",
			ScanType:    "Secrets",
			Enabled:     true,
		},
		{
			ID:          "vulnerability",
			Title:       "Insecure dependencies detection (critical and high severity)",
			Description: "Detects insecure dependencies (critical and high severity) by checking the libraries declared in the package manager and flagging used library versions with known security vulnerabilities.",
			Level:       "Error",
			Category:    "Security",
			SubCategory: "InsecureModulesLibraries",
			ScanType:    "SCA",
			Enabled:     true,
		},
		{
			ID:          "vulnerability_medium",
			Title:       "Insecure dependencies detection (medium severity)",
			Description: "Detects insecure dependencies (medium severity) by checking the libraries declared in the package manager and flagging used library versions with known security vulnerabilities.",
			Level:       "Warning",
			Category:    "Security",
			SubCategory: "InsecureModulesLibraries",
			ScanType:    "SCA",
			Enabled:     true,
		},
		{
			ID:          "vulnerability_minor",
			Title:       "Insecure dependencies detection (minor severity)",
			Description: "Detects insecure dependencies (minor severity) by checking the libraries declared in the package manager and flagging used library versions with known security vulnerabilities.",
			Level:       "Info",
			Category:    "Security",
			SubCategory: "InsecureModulesLibraries",
			ScanType:    "SCA",
			Enabled:     true,
		},
	}
}
