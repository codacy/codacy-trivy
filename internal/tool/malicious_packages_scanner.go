package tool

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/samber/lo"
	"golang.org/x/mod/semver"
)

// MaliciousPackagesIndexPath is the default path to the malicious package index.
const MaliciousPackagesIndexPath = "/dist/cache/codacy-trivy/openssf-malicious-packages-index.json.gz"

// maliciousPackage represents a shallow representation of an Open Source Vulnerability (OSV).
// Although it's schema is generic, it is guaranteed that it is only instantiated for Malicious Package vulnerabilities.
//
// See https://ossf.github.io/osv-schema/
type maliciousPackage struct {
	// OpenSSF identifier of the malicious package.
	ID string `json:"id"`
	// A summary of why the package is malicious.
	Summary string `json:"summary"`
	// The versions of the malicious package.
	// The version syntax is the one defined by the package ecosystem where the malicious package is deployed.
	Versions []string `json:"versions"`
	// The range of versions considered malicious.
	// This is usually defined if `Versions` is empty, but sometimes both are defined.
	Ranges []maliciousPackageRange `json:"ranges"`
}

// matchesVersion checks if the reported malicious package versions match version.
//
// `Ranges` is only checked if there is no direct match in `Versions`.
func (o maliciousPackage) matchesVersion(version string) bool {
	if slices.Contains(o.Versions, version) {
		return true
	}
	for _, affectedRange := range o.Ranges {
		if affectedRange.matchesVersion(version) {
			return true
		}
	}
	return false
}

// maliciousPackageRange represents range of versions considered malicious.
//
// See https://ossf.github.io/osv-schema/#affectedranges-field
type maliciousPackageRange struct {
	Type   string                       `json:"type"`
	Events []maliciousPackageRangeEvent `json:"events"`
}

// matchesVersion checks if version matches any of the range events but only if range is of type '[SEMVER]'.
//
// [SEMVER]: https://ossf.github.io/osv-schema/#affectedrangestype-field
func (r maliciousPackageRange) matchesVersion(version string) bool {
	if r.Type != "SEMVER" {
		return false
	}

	for _, event := range r.Events {
		if event.matchesVersion(version) {
			return true
		}
	}
	return false
}

// maliciousPackageRangeEvent describes a version that either fixed or introduced a vulnerability.
//
// See https://ossf.github.io/osv-schema/#affectedrangesevents-fields
type maliciousPackageRangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// matchesVersion checks if version is after Introduced or before Fixed.
//
// According to [OSV schema], either 'fixed' or 'introduced' are defined in an event, but not both.
//
// [OSV schema]: https://ossf.github.io/osv-schema/#requirements
func (e maliciousPackageRangeEvent) matchesVersion(version string) bool {
	if e.Introduced != "" {
		return semverCompare(version, e.Fixed) >= 0
	}
	if e.Fixed != "" {
		return semverCompare(version, e.Fixed) < 0
	}
	return false
}

// maliciousPackagesByEcosystemAndName maps ecosystem names to vulnerable packages.
type maliciousPackagesByEcosystemAndName map[string]maliciousPackagesByName

// maliciousPackagesByName maps malicious package names to their OSV entries.
type maliciousPackagesByName map[string][]maliciousPackage

// MaliciousPackagesScanner handles scanning for malicious packages.
// It expects an index of data in the OSV format.
//
// See https://ossf.github.io/osv-schema/
type MaliciousPackagesScanner struct {
	index maliciousPackagesByEcosystemAndName
}

// NewMaliciousPackagesScanner creates a new OpenSSF malicious packages scanner and loads
// malicious data from disk, as defined by the build process of this tool.
func NewMaliciousPackagesScanner(indexPath string) (*MaliciousPackagesScanner, error) {
	index, err := loadIndex(indexPath)
	if err != nil {
		return nil, err
	}

	return &MaliciousPackagesScanner{index: index}, nil
}

// Scan scans the given Trivy report for malicious packages.
func (s MaliciousPackagesScanner) Scan(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	maliciousPackagesEnabled := lo.SomeBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDMaliciousPackages
	})
	if !maliciousPackagesEnabled {
		return []codacy.Result{}
	}

	var issues []codacy.Issue
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			// For now we require PURL to be defined, but in the future we can try to infer it.
			if pkg.Identifier.PURL == nil {
				continue
			}

			pkgEcosystem := osvPackageEcosystem(pkg.Identifier.PURL.Type)
			maliciousPkgs, ok := s.index[pkgEcosystem]
			if !ok {
				continue
			}
			maliciousPkg, ok := maliciousPkgs[strings.ToLower(pkg.Name)]
			if !ok {
				continue
			}

			for _, candidate := range maliciousPkg {
				if pkg.Version != "" && candidate.matchesVersion(pkg.Version) {

					var lineNumber int
					if len(pkg.Locations) > 0 {
						lineNumber = pkg.Locations[0].StartLine
					} else {
						lineNumber = fallbackSearchForLineNumber(toolExecution.SourceDir, result.Target, pkg.Name)
					}

					issue := codacy.Issue{
						File:      result.Target,
						Line:      lineNumber,
						Message:   fmt.Sprintf("%s - %s@%s", candidate.Summary, pkg.Name, pkg.Version),
						PatternID: ruleIDMaliciousPackages,
						SourceID:  candidate.ID,
					}
					issues = append(issues, issue)
				}
			}

		}
	}

	return mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(issues, *toolExecution.Files))
}

// loadIndex attempts to load into memory the gzipped prebuilt index.
func loadIndex(indexPath string) (maliciousPackagesByEcosystemAndName, error) {
	f, err := os.Open(indexPath)
	if err != nil {
		return nil, &ToolError{msg: "Failed to open malicious package index", w: err}
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, &ToolError{msg: "Failed to read malicious package index", w: err}
	}
	defer gz.Close()

	var idx maliciousPackagesByEcosystemAndName
	if err := json.NewDecoder(gz).Decode(&idx); err != nil {
		return nil, &ToolError{msg: "Failed to decode malicious package index", w: err}
	}
	return idx, nil
}

// semverCompare compares two versions, handling both with and without "v" prefix.
//
// See [semver.Compare] documentation.
//
// [semver.Compare]: https://pkg.go.dev/golang.org/x/mod/semver#Compare
func semverCompare(v1, v2 string) int {
	// Ensure versions have "v" prefix for semver.Compare
	normalizeVersion := func(version string) string {
		if !strings.HasPrefix(version, "v") {
			return "v" + version
		}
		return version
	}

	// Ensure both versions have consistent prefix handling
	return semver.Compare(normalizeVersion(v1), normalizeVersion(v2))
}

// osvPackageEcosystem returns the corresponding Ecosystem defined by the OSV schema, for the PURL type of a package identified by Trivy.
//
// See https://ossf.github.io/osv-schema/#affectedpackage-field
func osvPackageEcosystem(purlType string) string {
	lowerPurlType := strings.ToLower(purlType)
	switch lowerPurlType {
	case "golang":
		return "go"
	case "gem":
		return "rubygems"
	case "cargo":
		return "crates.io"
	default:
		return lowerPurlType
	}
}
