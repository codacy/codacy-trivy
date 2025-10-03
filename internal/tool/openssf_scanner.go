package tool

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/samber/lo"
	"golang.org/x/mod/semver"
)

const (
	openssfCacheDir  = "/dist/cache/openssf-malicious-packages"
	openssfIndexPath = "/dist/cache/openssf-index.json.gz"
)

// Minimal OSV fields we care about
type osvRange struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced string `json:"introduced,omitempty"`
		Fixed      string `json:"fixed,omitempty"`
	} `json:"events"`
}

// Shallow entry stored in the index
type osvShallow struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

// EcosystemIndex maps ecosystem names to package indices
type EcosystemIndex map[string]PackageIndex

// PackageIndex maps package names to their malicious entries
type PackageIndex map[string][]osvShallow

// OpenSSFScanner handles scanning for malicious packages using an indexed DB
type OpenSSFScanner struct {
	// index maps ecosystem names to package indices for efficient lookups
	index EcosystemIndex
}

// NewOpenSSFScanner creates a new OpenSSF malicious packages scanner
func NewOpenSSFScanner() *OpenSSFScanner {
	return &OpenSSFScanner{
		index: make(EcosystemIndex),
	}
}

// ScanForMaliciousPackages scans the given report for malicious packages
func (s *OpenSSFScanner) ScanForMaliciousPackages(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var results []codacy.Result
	maliciousPackagesEnabled := lo.SomeBy(*toolExecution.Patterns, func(p codacy.Pattern) bool {
		return p.ID == ruleIDMaliciousPackages
	})
	if !maliciousPackagesEnabled {
		return results
	}

	if err := s.ensureIndexLoaded(); err != nil {
		log.Printf("Warning: Failed to load OpenSSF malicious packages database: %v", err)
		return results
	}

	results = append(results, s.scanReportPackages(report, toolExecution)...)
	results = append(results, s.scanKnownManifestsIfNoResults(report, toolExecution)...)
	return results
}

// scanReportPackages processes Trivy results and detects malicious packages
func (s *OpenSSFScanner) scanReportPackages(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var out []codacy.Result
	for _, r := range report.Results {
		out = append(out, s.scanSingleResult(r, toolExecution)...)
	}
	return out
}

// scanSingleResult handles a single Trivy result target
func (s *OpenSSFScanner) scanSingleResult(result ptypes.Result, toolExecution codacy.ToolExecution) []codacy.Result {
	var out []codacy.Result
	// If Trivy found no packages for a manifest, try parsing it directly
	if len(result.Packages) == 0 && strings.HasSuffix(result.Target, "package.json") {
		return s.scanNpmManifest(toolExecution.SourceDir, result.Target)
	}

	for _, pkg := range result.Packages {
		if issues := s.checkPackage(pkg, result.Target, toolExecution); len(issues) > 0 {
			out = append(out, issues...)
		}
	}
	return out
}

// checkPackage checks a single package for malicious versions
func (s *OpenSSFScanner) checkPackage(pkg ftypes.Package, target string, toolExecution codacy.ToolExecution) []codacy.Result {
	pkgType := s.getPackageType(pkg)
	pkgNameLower := strings.ToLower(pkg.Name)

	// If we can't determine package type from PURL, try to infer it from the target file
	if pkgType == "" {
		pkgType = s.inferPackageTypeFromTarget(target)
	}

	candidates := s.lookup(pkgType, pkgNameLower)
	if len(candidates) == 0 {
		return nil
	}

	for _, cand := range candidates {
		if s.versionMatches(pkg.Version, cand.Versions, cand.Ranges) {
			return s.createIssue(pkg, target, cand, toolExecution)
		}
	}
	return nil
}

// inferPackageTypeFromTarget tries to infer the package type from the target file path
func (s *OpenSSFScanner) inferPackageTypeFromTarget(target string) string {
	switch {
	case strings.HasSuffix(target, "package.json"):
		return "npm"
	case strings.HasSuffix(target, "package-lock.json"):
		return "npm"
	case strings.HasSuffix(target, "yarn.lock"):
		return "npm"
	case strings.HasSuffix(target, "go.mod"):
		return "golang"
	case strings.HasSuffix(target, "requirements.txt"):
		return "pypi"
	case strings.HasSuffix(target, "Pipfile"):
		return "pypi"
	case strings.HasSuffix(target, "poetry.lock"):
		return "pypi"
	case strings.HasSuffix(target, "pom.xml"):
		return "maven"
	case strings.HasSuffix(target, "build.gradle"):
		return "gradle"
	default:
		return ""
	}
}

// getPackageType extracts the package type from PURL
func (s *OpenSSFScanner) getPackageType(pkg ftypes.Package) string {
	if pkg.Identifier.PURL != nil {
		return strings.ToLower(pkg.Identifier.PURL.Type)
	}
	return ""
}

// getPackageDisplayName returns a display name for the package, handling nil PURLs
func (s *OpenSSFScanner) getPackageDisplayName(pkg ftypes.Package) string {
	if pkg.Identifier.PURL != nil {
		// Use the same logic as the main tool for consistency
		purlStripPkg := strings.TrimPrefix(pkg.Identifier.PURL.ToString(), "pkg:")
		if ppp, err := url.PathUnescape(purlStripPkg); err == nil {
			return ppp
		}
		return purlStripPkg
	}
	// Fallback to package name when PURL is not available
	return pkg.Name
}

// createIssue creates a malicious package issue
func (s *OpenSSFScanner) createIssue(pkg ftypes.Package, target string, cand osvShallow, toolExecution codacy.ToolExecution) []codacy.Result {
	lineNumber := s.findPackageLineNumber(toolExecution.SourceDir, target, pkg.Name)
	issue := codacy.Issue{
		File:      target,
		Message:   fmt.Sprintf("Malicious package detected: %s@%s - %s", pkg.Name, pkg.Version, cand.Summary),
		Line:      lineNumber,
		PatternID: ruleIDMaliciousPackages,
		SourceID:  cand.ID,
	}

	return []codacy.Result{issue}
}

// scanKnownManifestsIfNoResults checks known manifests when Trivy produced no results
func (s *OpenSSFScanner) scanKnownManifestsIfNoResults(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var out []codacy.Result
	if toolExecution.Files == nil {
		return out
	}
	for _, f := range *toolExecution.Files {
		if strings.HasSuffix(f, "package.json") {
			out = append(out, s.scanNpmManifest(toolExecution.SourceDir, f)...)
		}
	}
	return out
}

type npmPkg struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (s *OpenSSFScanner) scanNpmManifest(sourceDir, relativePath string) []codacy.Result {
	pj, err := s.parseNpmPackage(sourceDir, relativePath)
	if err != nil {
		return nil
	}

	var allResults []codacy.Result
	allResults = append(allResults, s.checkNpmDependencies(pj.Dependencies, sourceDir, relativePath)...)
	allResults = append(allResults, s.checkNpmDependencies(pj.DevDependencies, sourceDir, relativePath)...)
	allResults = append(allResults, s.checkNpmDependencies(pj.PeerDependencies, sourceDir, relativePath)...)
	allResults = append(allResults, s.checkNpmDependencies(pj.OptionalDependencies, sourceDir, relativePath)...)
	return allResults
}

// parseNpmPackage parses an npm package.json file
func (s *OpenSSFScanner) parseNpmPackage(sourceDir, relativePath string) (*npmPkg, error) {
	full := filepath.Join(sourceDir, relativePath)
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}

	var pj npmPkg
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, err
	}
	return &pj, nil
}

// checkNpmDependencies checks npm dependencies for malicious packages
func (s *OpenSSFScanner) checkNpmDependencies(dependencies map[string]string, sourceDir, relativePath string) []codacy.Result {
	var out []codacy.Result
	if dependencies == nil {
		return out
	}
	for name, ver := range dependencies {
		if issue := s.checkNpmDependency(name, ver, sourceDir, relativePath); issue != nil {
			out = append(out, *issue)
		}
	}
	return out
}

// checkNpmDependency checks a single npm dependency
func (s *OpenSSFScanner) checkNpmDependency(name, ver, sourceDir, relativePath string) *codacy.Issue {
	pkgNameLower := strings.ToLower(name)
	candidates := s.lookup("npm", pkgNameLower)
	if len(candidates) == 0 {
		return nil
	}

	for _, cand := range candidates {
		if s.versionMatches(ver, cand.Versions, cand.Ranges) {
			lineNumber := s.findPackageLineNumber(sourceDir, relativePath, name)
			issue := codacy.Issue{
				File:      relativePath,
				Message:   fmt.Sprintf("Malicious package detected: %s@%s - %s", name, ver, cand.Summary),
				Line:      lineNumber,
				PatternID: ruleIDMaliciousPackages,
				SourceID:  cand.ID,
			}
			return &issue
		}
	}
	return nil
}

func (s *OpenSSFScanner) lookup(ecosystemLower, pkgLower string) []osvShallow {
	pkgs := s.index[ecosystemLower]
	if pkgs == nil {
		return nil
	}
	return pkgs[pkgLower]
}

// ensureIndexLoaded loads the prebuilt index
func (s *OpenSSFScanner) ensureIndexLoaded() error {
	loaded, err := s.tryLoadPrebuiltIndex()
	if err != nil {
		return err
	}
	if !loaded {
		return fmt.Errorf("failed to load prebuilt OpenSSF index")
	}
	return nil
}

// tryLoadPrebuiltIndex attempts to load the gzipped prebuilt index
func (s *OpenSSFScanner) tryLoadPrebuiltIndex() (bool, error) {
	indexPath := openssfIndexPath
	fi, err := os.Stat(indexPath)
	if err != nil || fi.IsDir() {
		return false, nil
	}
	f, err := os.Open(indexPath)
	if err != nil {
		return false, nil
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false, nil
	}
	defer gz.Close()
	dec := json.NewDecoder(gz)
	var idx EcosystemIndex
	if err := dec.Decode(&idx); err != nil {
		return false, nil
	}
	s.index = idx
	return true, nil
}

// versionMatches checks if a version matches the malicious package criteria
func (s *OpenSSFScanner) versionMatches(version string, affectedVersions []string, ranges []osvRange) bool {
	if slices.Contains(affectedVersions, version) {
		return true
	}
	for _, versionRange := range ranges {
		if (versionRange.Type == "SEMVER" || versionRange.Type == "ECOSYSTEM") && s.checkSingleVersionRange(version, versionRange.Events) {
			return true
		}
	}
	return false
}

func (s *OpenSSFScanner) checkSingleVersionRange(version string, events []struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}) bool {
	for _, event := range events {
		if s.isVersionInRange(version, event) {
			return true
		}
	}
	return false
}

// isVersionInRange checks if a version falls within a specific event range
func (s *OpenSSFScanner) isVersionInRange(version string, event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}) bool {
	if event.Introduced != "" && event.Fixed != "" {
		return s.isVersionBetween(version, event.Introduced, event.Fixed)
	}
	if event.Introduced != "" {
		return s.isVersionAtLeast(version, event.Introduced)
	}
	return false
}

// isVersionBetween checks if version is >= introduced and < fixed
func (s *OpenSSFScanner) isVersionBetween(version, introduced, fixed string) bool {
	return s.semverCompare(version, introduced) >= 0 &&
		s.semverCompare(version, fixed) < 0
}

// isVersionAtLeast checks if version is >= introduced
func (s *OpenSSFScanner) isVersionAtLeast(version, introduced string) bool {
	return s.semverCompare(version, introduced) >= 0
}

// semverCompare compares two versions, handling both with and without "v" prefix
func (s *OpenSSFScanner) semverCompare(v1, v2 string) int {
	// Ensure both versions have consistent prefix handling
	v1Normalized := s.normalizeVersion(v1)
	v2Normalized := s.normalizeVersion(v2)
	return semver.Compare(v1Normalized, v2Normalized)
}

// normalizeVersion ensures version has "v" prefix for semver.Compare
func (s *OpenSSFScanner) normalizeVersion(version string) string {
	if version == "" {
		return "v0.0.0"
	}
	if !strings.HasPrefix(version, "v") {
		return "v" + version
	}
	return version
}

func (s *OpenSSFScanner) findPackageLineNumber(sourceDir, fileName, pkgName string) int {
	return fallbackSearchForLineNumber(sourceDir, fileName, pkgName)
}
