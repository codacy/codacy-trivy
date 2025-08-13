package tool

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"golang.org/x/mod/semver"
)

const (
	openssfCacheDir = "/dist/cache/openssf-malicious-packages"
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
		Versions []string  `json:"versions,omitempty"`
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
		fmt.Printf("Warning: Failed to load OpenSSF malicious packages database: %v\n", err)
		return results
	}

	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			pkgType := ""
			if pkg.Identifier.PURL != nil {
				pkgType = strings.ToLower(pkg.Identifier.PURL.Type)
			}
			pkgNameLower := strings.ToLower(pkg.Name)

			candidates := s.lookup(pkgType, pkgNameLower)
			if len(candidates) == 0 {
				continue
			}
			// Check version against candidates
			for _, cand := range candidates {
				if s.versionMatches(pkg.Version, cand.Versions, cand.Ranges) {
					lineNumber := s.findPackageLineNumber(toolExecution.SourceDir, result.Target, pkg.Name)
					issue := codacy.Issue{
						File:      result.Target,
						Message:   fmt.Sprintf("Malicious package detected: %s@%s - %s", pkg.Name, pkg.Version, cand.Summary),
						Line:      lineNumber,
						PatternID: ruleIDMaliciousPackages,
						SourceID:  cand.ID,
					}
					if s.shouldAnalyzeFile(toolExecution.Files, result.Target) {
						results = append(results, issue)
					}
					break
				}
			}
		}
	}
	return results
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

	// Prefer prebuilt index if present
	if fi, err := os.Stat(openssfIndexPath); err == nil && !fi.IsDir() {
		f, err := os.Open(openssfIndexPath)
		if err == nil {
			defer f.Close()
			gz, err := gzip.NewReader(f)
			if err == nil {
				defer gz.Close()
				dec := json.NewDecoder(gz)
				var idx map[string]map[string][]osvShallow
				if err := dec.Decode(&idx); err == nil {
					s.index = idx
					s.indexBuilt = true
					return nil
				}
			}
		}
	}

	// Fallback: build from individual files
	var files []string
	if err := filepath.Walk(openssfCacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil { return err }
		if info.IsDir() { return nil }
		if strings.HasSuffix(path, ".json") { files = append(files, path) }
		return nil
	}); err != nil {
		return fmt.Errorf("walk openssf dir: %w", err)
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 4 { workers = 4 }
	fileCh := make(chan string, 1024)
	var wg sync.WaitGroup
	var idxMu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range fileCh {
				data, err := ioutil.ReadFile(p)
				if err != nil { continue }
				var f osvFile
				if err := json.Unmarshal(data, &f); err != nil { continue }
				for _, aff := range f.Affected {
					eco := strings.ToLower(aff.Package.Ecosystem)
					name := strings.ToLower(aff.Package.Name)
					if eco == "" || name == "" { continue }
					entry := osvShallow{ID: f.ID, Summary: f.Summary, Versions: aff.Versions, Ranges: aff.Ranges}
					idxMu.Lock()
					m, ok := s.index[eco]
					if !ok { m = make(map[string][]osvShallow); s.index[eco] = m }
					m[name] = append(m[name], entry)
					idxMu.Unlock()
				}
			}
		}()
	}
	for _, p := range files { fileCh <- p }
	close(fileCh)
	wg.Wait()

	s.indexBuilt = true
	return nil
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
		if event.Introduced != "" && event.Fixed != "" {
			if semver.Compare("v"+version, "v"+event.Introduced) >= 0 && semver.Compare("v"+version, "v"+event.Fixed) < 0 {
				return true
			}
		} else if event.Introduced != "" {
			if semver.Compare("v"+version, "v"+event.Introduced) >= 0 {
				return true
			}
		}
	}
	return false
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
