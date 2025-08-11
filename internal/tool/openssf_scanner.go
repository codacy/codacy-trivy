package tool

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"golang.org/x/mod/semver"
)

const (
	openssfCacheDir = "/dist/cache/openssf-malicious-packages"
)

// OSVEntry represents an entry in the OpenSSF malicious packages database (OSV format)
type OSVEntry struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges,omitempty"`
		Versions []string `json:"versions,omitempty"`
	} `json:"affected"`
}

// OpenSSFScanner handles scanning for malicious packages using the OpenSSF database
type OpenSSFScanner struct {
	maliciousPackages []OSVEntry
	loaded            bool
}

// NewOpenSSFScanner creates a new OpenSSF malicious packages scanner
func NewOpenSSFScanner() *OpenSSFScanner {
	return &OpenSSFScanner{
		maliciousPackages: []OSVEntry{},
		loaded:            false,
	}
}

// ScanForMaliciousPackages scans the given report for malicious packages
func (s *OpenSSFScanner) ScanForMaliciousPackages(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var results []codacy.Result

	// Check if malicious_packages pattern is enabled
	if !s.isPatternEnabled(toolExecution.Patterns, ruleIDMaliciousPackages) {
		return results
	}

	// Lazy load the database
	if err := s.ensureDatabaseLoaded(); err != nil {
		fmt.Printf("Warning: Failed to load OpenSSF malicious packages database: %v\n", err)
		return results
	}

	// Check each detected package against the malicious packages database
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			if maliciousEntry := s.findMaliciousPackage(pkg); maliciousEntry != nil {
				// Find the line number where this package is declared
				lineNumber := s.findPackageLineNumber(toolExecution.SourceDir, result.Target, pkg.Name)

				issue := codacy.Issue{
					File:      result.Target,
					Message:   fmt.Sprintf("Malicious package detected: %s@%s - %s", pkg.Name, pkg.Version, maliciousEntry.Summary),
					Line:      lineNumber,
					PatternID: ruleIDMaliciousPackages,
					SourceID:  maliciousEntry.ID,
				}

				// Only include issues for files that should be analyzed
				if s.shouldAnalyzeFile(toolExecution.Files, result.Target) {
					results = append(results, issue)
				}
			}
		}
	}

	return results
}

// ensureDatabaseLoaded loads the OpenSSF database if not already loaded
func (s *OpenSSFScanner) ensureDatabaseLoaded() error {
	if s.loaded {
		return nil
	}

	maliciousPackages, err := s.loadDatabase()
	if err != nil {
		return fmt.Errorf("failed to load OpenSSF database: %w", err)
	}

	s.maliciousPackages = maliciousPackages
	s.loaded = true
	return nil
}

// loadDatabase loads the OpenSSF malicious packages database from the cache directory
func (s *OpenSSFScanner) loadDatabase() ([]OSVEntry, error) {
	var maliciousPackages []OSVEntry

	// Walk through the OpenSSF cache directory and load all OSV files
	err := filepath.Walk(openssfCacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Some repositories may contain directories with names ending in .json; skip directories explicitly
		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		var entry OSVEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			// Log warning but continue processing other files
			fmt.Printf("Warning: Failed to parse OSV file %s: %v\n", path, err)
			return nil
		}

		maliciousPackages = append(maliciousPackages, entry)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return maliciousPackages, nil
}

// findMaliciousPackage checks if a package matches any entry in the malicious packages database
func (s *OpenSSFScanner) findMaliciousPackage(pkg ftypes.Package) *OSVEntry {
	for _, malicious := range s.maliciousPackages {
		for _, affected := range malicious.Affected {
			// Extract PURL type when available
			pkgType := ""
			if pkg.Identifier.PURL != nil {
				pkgType = pkg.Identifier.PURL.Type
			}
			if affected.Package.Name == pkg.Name && s.ecosystemMatches(affected.Package.Ecosystem, pkgType) {
				if s.versionMatches(pkg.Version, affected.Versions, affected.Ranges) {
					return &malicious
				}
			}
		}
	}
	return nil
}

// ecosystemMatches maps OpenSSF ecosystems to PURL types and compares with the detected PURL type
func (s *OpenSSFScanner) ecosystemMatches(osvEcosystem string, purlType string) bool {
	osv := strings.ToLower(osvEcosystem)
	purl := strings.ToLower(purlType)

	osvToPurl := map[string]string{
		"npm":       "npm",
		"pypi":      "pypi",
		"maven":     "maven",
		"nuget":     "nuget",
		"rubygems":  "gem",
		"go":        "golang",
		"crates.io": "cargo",
		"packagist": "composer",
	}

	if mapped, ok := osvToPurl[osv]; ok {
		return mapped == purl
	}
	// Fallback: compare raw ecosystem and purl type
	return osv == purl
}

// versionMatches checks if a version matches the malicious package criteria
func (s *OpenSSFScanner) versionMatches(version string, affectedVersions []string, ranges []struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced string `json:"introduced,omitempty"`
		Fixed      string `json:"fixed,omitempty"`
	} `json:"events"`
}) bool {
	// Check exact version matches first (most common case)
	if s.checkExactVersionMatch(version, affectedVersions) {
		return true
	}

	// Check version ranges
	return s.checkVersionRanges(version, ranges)
}

// checkExactVersionMatch checks for exact version matches
func (s *OpenSSFScanner) checkExactVersionMatch(version string, affectedVersions []string) bool {
	for _, affectedVersion := range affectedVersions {
		if version == affectedVersion {
			return true
		}
	}
	return false
}

// checkVersionRanges checks if version falls within any of the specified ranges
func (s *OpenSSFScanner) checkVersionRanges(version string, ranges []struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced string `json:"introduced,omitempty"`
		Fixed      string `json:"fixed,omitempty"`
	} `json:"events"`
}) bool {
	for _, versionRange := range ranges {
		if versionRange.Type == "SEMVER" || versionRange.Type == "ECOSYSTEM" {
			if s.checkSingleVersionRange(version, versionRange.Events) {
				return true
			}
		}
	}
	return false
}

// checkSingleVersionRange checks if version falls within a single range
func (s *OpenSSFScanner) checkSingleVersionRange(version string, events []struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}) bool {
	for _, event := range events {
		if event.Introduced != "" && event.Fixed != "" {
			// Version is in range if >= introduced and < fixed
			if semver.Compare("v"+version, "v"+event.Introduced) >= 0 &&
				semver.Compare("v"+version, "v"+event.Fixed) < 0 {
				return true
			}
		} else if event.Introduced != "" {
			// Version is affected if >= introduced (no upper bound)
			if semver.Compare("v"+version, "v"+event.Introduced) >= 0 {
				return true
			}
		}
	}
	return false
}

// findPackageLineNumber attempts to find the line number where a package is declared
func (s *OpenSSFScanner) findPackageLineNumber(sourceDir, fileName, pkgName string) int {
	// Reuse the existing fallback search function
	return fallbackSearchForLineNumber(sourceDir, fileName, pkgName)
}

// isPatternEnabled checks if a specific pattern is enabled in the tool execution
func (s *OpenSSFScanner) isPatternEnabled(patterns *[]codacy.Pattern, patternID string) bool {
	if patterns == nil {
		return false
	}

	for _, pattern := range *patterns {
		if pattern.ID == patternID {
			return true
		}
	}
	return false
}

// shouldAnalyzeFile checks if a file should be analyzed based on the provided list of files to analyze
func (s *OpenSSFScanner) shouldAnalyzeFile(knownFiles *[]string, fileName string) bool {
	if knownFiles == nil {
		return true // If no files are provided, analyze everything
	}

	for _, file := range *knownFiles {
		if file == fileName {
			return true
		}
	}
	return false
}
