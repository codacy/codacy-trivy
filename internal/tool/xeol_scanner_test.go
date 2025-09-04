package tool

import (
	"os"
	"path/filepath"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/stretchr/testify/assert"
)

func TestXeolScanner_ScanForEOLPackages_NoPatterns(t *testing.T) {
	scanner := NewXeolScanner()

	report := ptypes.Report{}
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{},
	}

	results := scanner.ScanForEOLPackages(report, toolExecution)
	assert.Empty(t, results, "Should return empty results when no EOL patterns are enabled")
}

func TestXeolScanner_ScanForEOLPackages_NoDatabase(t *testing.T) {
	scanner := NewXeolScanner()

	report := ptypes.Report{}
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{ID: ruleIDEOLPackages},
		},
	}

	// Set environment variable to non-existent database
	tempDir := t.TempDir()
	nonExistentDB := filepath.Join(tempDir, "nonexistent.db")
	os.Setenv("XEOL_DB_PATH", nonExistentDB)
	defer os.Unsetenv("XEOL_DB_PATH")

	results := scanner.ScanForEOLPackages(report, toolExecution)
	assert.Empty(t, results, "Should return empty results when database doesn't exist")
}

func TestXeolScanner_isEOLPatternEnabled(t *testing.T) {
	scanner := NewXeolScanner()

	tests := []struct {
		name     string
		patterns []codacy.Pattern
		expected bool
	}{
		{
			name:     "no patterns",
			patterns: []codacy.Pattern{},
			expected: false,
		},
		{
			name: "has eol_packages pattern",
			patterns: []codacy.Pattern{
				{ID: ruleIDEOLPackages},
			},
			expected: true,
		},
		{
			name: "has eol_packages_soon pattern",
			patterns: []codacy.Pattern{
				{ID: ruleIDEOLPackagesSoon},
			},
			expected: true,
		},
		{
			name: "has other patterns",
			patterns: []codacy.Pattern{
				{ID: ruleIDSecret},
				{ID: ruleIDMaliciousPackages},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isEOLPatternEnabled(&tt.patterns)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestXeolScanner_packageMatches(t *testing.T) {
	scanner := NewXeolScanner()

	pkg := ftypes.Package{Name: "django"}
	product := eolProduct{Name: "Django"}

	result := scanner.packageMatches(pkg, product)
	assert.True(t, result, "Should match packages case-insensitively")
}
