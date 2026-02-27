package docgen

import (
	"fmt"

	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
)

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

func secretRule() Rules {
	return Rules{{
		ID:          "secret",
		Title:       "Secret detection",
		Description: "Detects secrets that should not be committed to a repository or otherwise disclosed, such as secret keys, passwords, and authentication tokens from multiple products.",
		Level:       "Error",
		Category:    "Security",
		SubCategory: "Cryptography",
		ScanType:    "Secrets",
		Enabled:     true,
	}}
}

func vulnerabilityRules() Rules {
	const descPrefix = "Detects insecure dependencies (%s severity) by checking the libraries declared in the package manager and flagging used library versions with known security vulnerabilities."
	return Rules{
		{"vulnerability_critical", "Insecure dependencies detection (critical severity)", fmt.Sprintf(descPrefix, "critical"), "Error", "Security", "InsecureModulesLibraries", "SCA", true},
		{"vulnerability_high", "Insecure dependencies detection (high severity)", fmt.Sprintf(descPrefix, "high"), "High", "Security", "InsecureModulesLibraries", "SCA", true},
		{"vulnerability_medium", "Insecure dependencies detection (medium severity)", fmt.Sprintf(descPrefix, "medium"), "Warning", "Security", "InsecureModulesLibraries", "SCA", true},
		{"vulnerability_minor", "Insecure dependencies detection (minor severity)", fmt.Sprintf(descPrefix, "minor"), "Info", "Security", "InsecureModulesLibraries", "SCA", true},
	}
}

func maliciousPackagesRule() Rules {
	return Rules{{
		ID:          "malicious_packages",
		Title:       "Malicious packages detection",
		Description: "Detects malicious packages identified in the OpenSSF Malicious Packages database, including typosquatting attacks, dependency confusion, and packages with malicious payloads.",
		Level:       "Error",
		Category:    "Security",
		SubCategory: "InsecureModulesLibraries",
		ScanType:    "SCA",
		Enabled:     true,
	}}
}

func eolRules() Rules {
	return Rules{
		{"eol_critical", "End-of-life package (obsolete)", "Detects packages that have reached end-of-life and are no longer supported. These dependencies no longer receive security updates and should be upgraded.", "Error", "Security", "InsecureModulesLibraries", "SCA", true},
		{"eol_high", "End-of-life package (within 1 month)", "Detects packages that will reach end-of-life within one month. Plan to upgrade before support ends.", "High", "Security", "InsecureModulesLibraries", "SCA", true},
		{"eol_medium", "End-of-life package (within 6 months)", "Detects packages that will reach end-of-life within six months. Consider upgrading to a supported version.", "Warning", "Security", "InsecureModulesLibraries", "SCA", true},
		{"eol_minor", "End-of-life package (beyond 6 months)", "Detects packages that will reach end-of-life in more than six months. Track for future upgrade planning.", "Info", "Security", "InsecureModulesLibraries", "SCA", true},
	}
}

// trivyRules returns all `codacy-trivy` Rules.
func trivyRules() Rules {
	return append(append(append(secretRule(), vulnerabilityRules()...), maliciousPackagesRule()...), eolRules()...)
}
