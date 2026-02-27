package tool

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestSeverityFromEolDate(t *testing.T) {
	tests := []struct {
		name     string
		eolDate  string
		wantRule string
		wantErr  bool
	}{
		{"obsolete (past)", "2020-01-01", ruleIDEOLCritical, false},
		{"empty", "", "", true},
		{"invalid format", "not-a-date", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := severityFromEolDate(tt.eolDate)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantRule, got)
		})
	}
	// Relative dates: use now + offset so tests are stable
	now := time.Now().UTC()
	highDate := now.AddDate(0, 0, 15).Format("2006-01-02")   // 15 days
	mediumDate := now.AddDate(0, 2, 0).Format("2006-01-02") // ~60 days
	minorDate := now.AddDate(1, 0, 0).Format("2006-01-02")  // 1 year
	t.Run("within 1 month", func(t *testing.T) {
		got, err := severityFromEolDate(highDate)
		assert.NoError(t, err)
		assert.Equal(t, ruleIDEOLHigh, got)
	})
	t.Run("within 6 months", func(t *testing.T) {
		got, err := severityFromEolDate(mediumDate)
		assert.NoError(t, err)
		assert.Equal(t, ruleIDEOLMedium, got)
	})
	t.Run("beyond 6 months", func(t *testing.T) {
		got, err := severityFromEolDate(minorDate)
		assert.NoError(t, err)
		assert.Equal(t, ruleIDEOLMinor, got)
	})
}

func TestEOLScanner_Scan_NoPatternEnabled(t *testing.T) {
	mockRunner := &mockEOLRunner{matches: []eolMatch{
		{PURL: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", EolDate: "2024-01-01"},
	}}
	s := NewEOLScanner(mockRunner)
	report := ptypes.Report{Results: []ptypes.Result{}}
	bom := &cdx.BOM{}
	patterns := []codacy.Pattern{{ID: ruleIDVulnerabilityCritical}}
	files := []string{"go.mod"}
	te := codacy.ToolExecution{Patterns: &patterns, Files: &files, SourceDir: t.TempDir()}

	result := s.Scan(report, te, bom)

	assert.Empty(t, result)
	assert.False(t, mockRunner.called, "runner should not be called when no EOL pattern enabled")
}

func TestEOLScanner_Scan_WithMockRunner(t *testing.T) {
	purlStr := "pkg:npm/lodash@4.17.21"
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target: "package-lock.json",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{Type: "npm", Name: "lodash", Version: "4.17.21"},
						},
						Name:     "lodash",
						Version:  "4.17.21",
						Locations: ftypes.Locations{{StartLine: 42}},
					},
				},
			},
		},
	}
	mockRunner := &mockEOLRunner{matches: []eolMatch{
		{PURL: purlStr, Name: "lodash", Version: "4.17.21", EolDate: "2024-06-01", CycleID: "4.x"},
	}}
	s := NewEOLScanner(mockRunner)
	bom := minimalBOM(t)
	patterns := []codacy.Pattern{{ID: ruleIDEOLCritical}}
	files := []string{"package-lock.json"}
	te := codacy.ToolExecution{Patterns: &patterns, Files: &files, SourceDir: t.TempDir()}

	result := s.Scan(report, te, bom)

	assert.True(t, mockRunner.called)
	assert.Len(t, result, 1)
	issue, ok := result[0].(codacy.Issue)
	assert.True(t, ok)
	assert.Equal(t, ruleIDEOLCritical, issue.PatternID)
	assert.Equal(t, "package-lock.json", issue.File)
	assert.Equal(t, 42, issue.Line)
	assert.Contains(t, issue.Message, "lodash@4.17.21")
	assert.Contains(t, issue.Message, "2024-06-01")
}

func TestEOLScanner_Scan_SeverityBands(t *testing.T) {
	purl := packageurl.NewPackageURL("npm", "", "pkg", "1.0.0", nil, "")
	purlStr := purl.ToString()
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target:   "package-lock.json",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{PURL: purl},
						Name:       "pkg",
						Version:    "1.0.0",
						Locations:  ftypes.Locations{{StartLine: 1}},
					},
				},
			},
		},
	}
	files := []string{"package-lock.json"}
	te := codacy.ToolExecution{Patterns: &[]codacy.Pattern{{ID: ruleIDEOLCritical}, {ID: ruleIDEOLHigh}, {ID: ruleIDEOLMedium}, {ID: ruleIDEOLMinor}}, Files: &files, SourceDir: t.TempDir()}
	bom := minimalBOM(t)

	now := time.Now().UTC()
	bands := []struct {
		eolDate string
		ruleID  string
	}{
		{"2020-01-01", ruleIDEOLCritical},
		{now.AddDate(0, 0, 15).Format("2006-01-02"), ruleIDEOLHigh},
		{now.AddDate(0, 2, 0).Format("2006-01-02"), ruleIDEOLMedium},
		{now.AddDate(1, 0, 0).Format("2006-01-02"), ruleIDEOLMinor},
	}
	for _, b := range bands {
		mockRunner := &mockEOLRunner{matches: []eolMatch{{PURL: purlStr, Name: "pkg", Version: "1.0.0", EolDate: b.eolDate}}}
		s := NewEOLScanner(mockRunner)
		result := s.Scan(report, te, bom)
		assert.Len(t, result, 1, "eol date %s should produce one issue", b.eolDate)
		issue := result[0].(codacy.Issue)
		assert.Equal(t, b.ruleID, issue.PatternID, "eol date %s", b.eolDate)
	}
}

func TestEOLScanner_Scan_FiltersKnownFiles(t *testing.T) {
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target:   "ExcludedLock.json",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: "npm", Name: "eol-pkg", Version: "1.0.0"}},
						Name:       "eol-pkg",
						Version:    "1.0.0",
						Locations:  ftypes.Locations{{StartLine: 10}},
					},
				},
			},
		},
	}
	mockRunner := &mockEOLRunner{matches: []eolMatch{
		{PURL: "pkg:npm/eol-pkg@1.0.0", Name: "eol-pkg", Version: "1.0.0", EolDate: "2024-01-01"},
	}}
	s := NewEOLScanner(mockRunner)
	bom := minimalBOM(t)
	patterns := []codacy.Pattern{{ID: ruleIDEOLCritical}}
	files := []string{"package-lock.json"} // ExcludedLock.json not in list
	te := codacy.ToolExecution{Patterns: &patterns, Files: &files, SourceDir: t.TempDir()}

	result := s.Scan(report, te, bom)

	assert.Empty(t, result)
}

func TestEOLScanner_Scan_NilBOM(t *testing.T) {
	s := NewEOLScanner(&mockEOLRunner{})
	patterns := []codacy.Pattern{{ID: ruleIDEOLCritical}}
	files := []string{}
	te := codacy.ToolExecution{Patterns: &patterns, Files: &files}

	result := s.Scan(ptypes.Report{}, te, nil)

	assert.Empty(t, result)
}

func TestEOLScanner_Scan_EmptyComponentsBOM(t *testing.T) {
	s := NewEOLScanner(&mockEOLRunner{})
	bom := &cdx.BOM{}
	patterns := []codacy.Pattern{{ID: ruleIDEOLCritical}}
	files := []string{}
	te := codacy.ToolExecution{Patterns: &patterns, Files: &files}

	result := s.Scan(ptypes.Report{}, te, bom)

	// Still runs runner (temp file written); mock returns empty
	assert.Empty(t, result)
}

func TestEOLScanner_Scan_NoLineNumberBecomesFileError(t *testing.T) {
	purl := packageurl.NewPackageURL("npm", "", "no-line-pkg", "1.0.0", nil, "")
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target:   "package-lock.json",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{PURL: purl},
						Name:       "no-line-pkg",
						Version:    "1.0.0",
						Locations:  nil, // no location
					},
				},
			},
		},
	}
	dir := t.TempDir()
	// No file with "no-line-pkg" in content -> fallback returns 0
	mockRunner := &mockEOLRunner{matches: []eolMatch{
		{PURL: purl.ToString(), Name: "no-line-pkg", Version: "1.0.0", EolDate: "2024-01-01"},
	}}
	s := NewEOLScanner(mockRunner)
	bom := minimalBOM(t)
	patterns := []codacy.Pattern{{ID: ruleIDEOLCritical}}
	files := []string{"package-lock.json"}
	te := codacy.ToolExecution{Patterns: &patterns, Files: &files, SourceDir: dir}

	result := s.Scan(report, te, bom)

	assert.Len(t, result, 1)
	fe, ok := result[0].(codacy.FileError)
	assert.True(t, ok)
	assert.Equal(t, "package-lock.json", fe.File)
	assert.Contains(t, fe.Message, "Line numbers")
}

func TestBuildPURLToLocation(t *testing.T) {
	purl := packageurl.NewPackageURL("npm", "", "lodash", "4.17.21", nil, "")
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target:   "package-lock.json",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{PURL: purl},
						Locations:  ftypes.Locations{{StartLine: 10}},
					},
				},
			},
		},
	}
	m := buildPURLToLocation(report)
	assert.Len(t, m, 1)
	loc, ok := m[purl.ToString()]
	assert.True(t, ok)
	assert.Equal(t, "package-lock.json", loc.target)
	assert.Equal(t, 10, loc.line)
}

func TestFindLocationByPackage(t *testing.T) {
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target:   "go.mod",
				Packages: []ftypes.Package{
					{Name: "stdlib", Version: "1.22", Locations: ftypes.Locations{{StartLine: 2}}},
				},
			},
		},
	}
	loc, ok := findLocationByPackage(report, "stdlib", "1.22")
	assert.True(t, ok)
	assert.Equal(t, "go.mod", loc.target)
	assert.Equal(t, 2, loc.line)

	_, ok = findLocationByPackage(report, "other", "1.0")
	assert.False(t, ok)
}

type mockEOLRunner struct {
	matches []eolMatch
	called  bool
}

func (m *mockEOLRunner) Run(sbomPath string) ([]eolMatch, error) {
	m.called = true
	return m.matches, nil
}

func minimalBOM(t *testing.T) *cdx.BOM {
	t.Helper()
	comps := []cdx.Component{}
	deps := []cdx.Dependency{}
	return &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_4,
		Version:      1,
		Components:   &comps,
		Dependencies: &deps,
	}
}
