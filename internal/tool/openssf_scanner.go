// Package tool implements the Codacy Trivy tool, including the OpenSSF malicious
// packages scanner and its prebuilt-index loading for performance.
package tool

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"golang.org/x/mod/semver"
)

const (
	openssfCacheDir  = "/dist/cache/openssf-malicious-packages"
	openssfIndexPath = "/dist/cache/openssf-index.json.gz"
)

func getOpenSSFIndexPath() string {
	if v := os.Getenv("OPENSSF_INDEX_PATH"); v != "" {
		return v
	}
	return openssfIndexPath
}

func getOpenSSFCacheDir() string {
	if v := os.Getenv("OPENSSF_CACHE_DIR"); v != "" {
		return v
	}
	return openssfCacheDir
}

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
	ID       string
	Summary  string
	Versions []string
	Ranges   []osvRange
}

// JSON structure used for decoding files
type osvFile struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Versions []string   `json:"versions,omitempty"`
		Ranges   []osvRange `json:"ranges,omitempty"`
	} `json:"affected"`
}

// OpenSSFScanner handles scanning for malicious packages using an indexed DB
type OpenSSFScanner struct {
	// index[ecosystemLower][packageLower] => list of entries
	index      map[string]map[string][]osvShallow
	indexBuilt bool
	mu         sync.RWMutex
}

// NewOpenSSFScanner creates a new OpenSSF malicious packages scanner
func NewOpenSSFScanner() *OpenSSFScanner {
	return &OpenSSFScanner{
		index: make(map[string]map[string][]osvShallow),
	}
}

// ScanForMaliciousPackages scans the given report for malicious packages
func (s *OpenSSFScanner) ScanForMaliciousPackages(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var results []codacy.Result
	if !s.isPatternEnabled(toolExecution.Patterns, ruleIDMaliciousPackages) {
		return results
	}

	if err := s.ensureIndexBuilt(); err != nil {
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
		return s.scanNpmManifest(toolExecution.SourceDir, result.Target, toolExecution.Files)
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

// getPackageType extracts the package type from PURL
func (s *OpenSSFScanner) getPackageType(pkg ftypes.Package) string {
	if pkg.Identifier.PURL != nil {
		return strings.ToLower(pkg.Identifier.PURL.Type)
	}
	return ""
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

	if s.shouldAnalyzeFile(toolExecution.Files, target) {
		return []codacy.Result{issue}
	}
	return nil
}

// scanKnownManifestsIfNoResults checks known manifests when Trivy produced no results
func (s *OpenSSFScanner) scanKnownManifestsIfNoResults(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var out []codacy.Result
	if len(report.Results) != 0 || toolExecution.Files == nil {
		return out
	}
	for _, f := range *toolExecution.Files {
		if strings.HasSuffix(f, "package.json") {
			out = append(out, s.scanNpmManifest(toolExecution.SourceDir, f, toolExecution.Files)...)
		}
	}
	return out
}

type npmPkg struct {
	Dependencies map[string]string `json:"dependencies"`
}

func (s *OpenSSFScanner) scanNpmManifest(sourceDir, relativePath string, knownFiles *[]string) []codacy.Result {
	if !s.shouldAnalyzeFile(knownFiles, relativePath) {
		return nil
	}

	pj, err := s.parseNpmPackage(sourceDir, relativePath)
	if err != nil {
		return nil
	}

	return s.checkNpmDependencies(pj.Dependencies, relativePath)
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
func (s *OpenSSFScanner) checkNpmDependencies(dependencies map[string]string, relativePath string) []codacy.Result {
	var out []codacy.Result
	for name, ver := range dependencies {
		if issue := s.checkNpmDependency(name, ver, relativePath); issue != nil {
			out = append(out, *issue)
		}
	}
	return out
}

// checkNpmDependency checks a single npm dependency
func (s *OpenSSFScanner) checkNpmDependency(name, ver, relativePath string) *codacy.Issue {
	pkgNameLower := strings.ToLower(name)
	candidates := s.lookup("npm", pkgNameLower)
	if len(candidates) == 0 {
		return nil
	}

	for _, cand := range candidates {
		if s.versionMatches(ver, cand.Versions, cand.Ranges) {
			issue := codacy.Issue{
				File:      relativePath,
				Message:   fmt.Sprintf("Malicious package detected: %s@%s - %s", name, ver, cand.Summary),
				Line:      1,
				PatternID: ruleIDMaliciousPackages,
				SourceID:  cand.ID,
			}
			return &issue
		}
	}
	return nil
}

func (s *OpenSSFScanner) lookup(ecosystemLower, pkgLower string) []osvShallow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pkgs := s.index[ecosystemLower]
	if pkgs == nil {
		return nil
	}
	return pkgs[pkgLower]
}

// ensureIndexBuilt builds the in-memory index once with concurrency
func (s *OpenSSFScanner) ensureIndexBuilt() error {
	s.mu.RLock()
	if s.indexBuilt {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.indexBuilt {
		return nil
	}

	loaded, err := s.tryLoadPrebuiltIndex()
	if err != nil {
		return err
	}
	if loaded {
		s.indexBuilt = true
		return nil
	}

	files, err := s.collectOSVFiles()
	if err != nil {
		return err
	}
	if err := s.buildIndexFromFiles(files); err != nil {
		return err
	}

	s.indexBuilt = true
	return nil
}

// tryLoadPrebuiltIndex attempts to load the gzipped prebuilt index
func (s *OpenSSFScanner) tryLoadPrebuiltIndex() (bool, error) {
	indexPath := getOpenSSFIndexPath()
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
	var idx map[string]map[string][]osvShallow
	if err := dec.Decode(&idx); err != nil {
		return false, nil
	}
	s.index = idx
	return true, nil
}

// collectOSVFiles walks the cache directory and returns all JSON files
func (s *OpenSSFScanner) collectOSVFiles() ([]string, error) {
	var files []string
	root := getOpenSSFCacheDir()
	if _, err := os.Stat(root); err != nil {
		// If the directory does not exist, return empty list (we rely on prebuilt index)
		return files, nil
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".json") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk openssf dir: %w", err)
	}
	return files, nil
}

// buildIndexFromFiles parses the OSV files concurrently and fills the index
func (s *OpenSSFScanner) buildIndexFromFiles(files []string) error {
	workers := runtime.GOMAXPROCS(0)
	if workers < 4 {
		workers = 4
	}
	fileCh := make(chan string, 1024)
	var wg sync.WaitGroup
	var idxMu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range fileCh {
				s.processOSVFile(p, &idxMu)
			}
		}()
	}
	for _, p := range files {
		fileCh <- p
	}
	close(fileCh)
	wg.Wait()
	return nil
}

// processOSVFile processes a single OSV file and adds entries to the index
func (s *OpenSSFScanner) processOSVFile(filePath string, idxMu *sync.Mutex) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var f osvFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("Warning: Failed to parse OSV file %s: %v", filePath, err)
		return
	}

	s.addAffectedPackagesToIndex(f, idxMu)
}

// addAffectedPackagesToIndex adds affected packages from an OSV file to the index
func (s *OpenSSFScanner) addAffectedPackagesToIndex(f osvFile, idxMu *sync.Mutex) {
	for _, aff := range f.Affected {
		eco := strings.ToLower(aff.Package.Ecosystem)
		name := strings.ToLower(aff.Package.Name)
		if eco == "" || name == "" {
			continue
		}

		entry := osvShallow{ID: f.ID, Summary: f.Summary, Versions: aff.Versions, Ranges: aff.Ranges}
		s.addEntryToIndex(eco, name, entry, idxMu)
	}
}

// addEntryToIndex adds a single entry to the index with proper locking
func (s *OpenSSFScanner) addEntryToIndex(eco, name string, entry osvShallow, idxMu *sync.Mutex) {
	idxMu.Lock()
	defer idxMu.Unlock()

	m, ok := s.index[eco]
	if !ok {
		m = make(map[string][]osvShallow)
		s.index[eco] = m
	}
	m[name] = append(m[name], entry)
}

// versionMatches checks if a version matches the malicious package criteria
func (s *OpenSSFScanner) versionMatches(version string, affectedVersions []string, ranges []osvRange) bool {
	for _, affectedVersion := range affectedVersions {
		if version == affectedVersion {
			return true
		}
	}
	for _, versionRange := range ranges {
		if versionRange.Type == "SEMVER" || versionRange.Type == "ECOSYSTEM" {
			if s.checkSingleVersionRange(version, versionRange.Events) {
				return true
			}
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
	return semver.Compare("v"+version, "v"+introduced) >= 0 &&
		semver.Compare("v"+version, "v"+fixed) < 0
}

// isVersionAtLeast checks if version is >= introduced
func (s *OpenSSFScanner) isVersionAtLeast(version, introduced string) bool {
	return semver.Compare("v"+version, "v"+introduced) >= 0
}

func (s *OpenSSFScanner) findPackageLineNumber(sourceDir, fileName, pkgName string) int {
	return fallbackSearchForLineNumber(sourceDir, fileName, pkgName)
}

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

func (s *OpenSSFScanner) shouldAnalyzeFile(knownFiles *[]string, fileName string) bool {
	if knownFiles == nil {
		return true
	}
	for _, file := range *knownFiles {
		if file == fileName {
			return true
		}
	}
	return false
}
