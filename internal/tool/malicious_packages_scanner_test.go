package tool

import (
	"compress/gzip"
	"os"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestScan(t *testing.T) {
	// Arrange
	index := maliciousPackagesByEcosystemAndName{
		"go": {
			"more-recent-malicious-package": {
				{
					ID:      "MAL-more-recent",
					Summary: "Malicious code in more-recent-malicious-package (go)",
					Ranges: []maliciousPackageRange{
						{
							Type: "SEMVER",
							Events: []maliciousPackageRangeEvent{
								{
									Introduced: "2",
								},
							},
						},
					},
				},
			},
		},
		"crates.io": {
			"older-malicious-package": {
				{
					ID:      "MAL-older",
					Summary: "Malicious code in older-malicious-package (crates.io)",
					Ranges: []maliciousPackageRange{
						{
							Type: "SEMVER",
							Events: []maliciousPackageRangeEvent{
								{
									Fixed: "2",
								},
							},
						},
					},
				},
			},
		},
		"rubygems": {
			"malicious-package-in-range": {
				{
					ID:      "MAL-in-range",
					Summary: "Malicious code in malicious-package-in-range (rubygems)",
					Ranges: []maliciousPackageRange{
						{
							Type: "SEMVER",
							Events: []maliciousPackageRangeEvent{
								{
									Introduced: "1",
								},
								{
									Fixed: "2",
								},
							},
						},
					},
				},
			},
		},
		"npm": {
			"malicious-package-with-exact-version": {
				{
					ID:       "MAL-exact-version",
					Summary:  "Malicious code in malicious-package-with-exact-version (npm)",
					Versions: []string{"1.2.3", "3.2.1"},
				},
			},
			"malicious-pacakge-with-unsupported-ecosystem-versioning": {
				{
					ID:      "MAL-unsupported-ecosystem-version",
					Summary: "Malicious code in malicious-package-with-unsupported-ecosystem-versioning (npm)",
					Ranges: []maliciousPackageRange{
						{
							Type: "ECOSYSTEM",
							Events: []maliciousPackageRangeEvent{
								{
									Introduced: "0",
								},
							},
						},
					},
				},
			},
		},
		"pypi": {
			"malicious-pacakge-with-supported-ecosystem-versioning": {
				{
					ID:      "MAL-supported-ecosystem-version",
					Summary: "Malicious code in malicious-pacakge-with-supported-ecosystem-versioning (pypi)",
					Ranges: []maliciousPackageRange{
						{
							Type: "ECOSYSTEM",
							Events: []maliciousPackageRangeEvent{
								{
									Introduced: "0",
								},
							},
						},
					},
				},
			},
		},
	}
	report := ptypes.Report{
		Results: []ptypes.Result{
			{
				Target: "go.mod",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "golang",
							},
						},
						Name:    "more-recent-malicious-package",
						Version: "1.0.1", // Before it became malicious
					},
					{
						Name:    "more-recent-malicious-package",
						Version: "2.0.1", // This would match but the package has no PURL
					},
				},
			},
			{
				Target: "Cargo.lock",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "cargo",
							},
						},
						Name:    "older-malicious-package",
						Version: "2.0.1", // After it was no longer malicious
					},
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "cargo",
							},
						},
						Name:    "older-malicious-package",
						Version: "1.9.0", // This would match and produce an issue but package has no line number information and issue is discarded.
					},
				},
			},
			{
				Target: "Gemfile.lock",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "gem",
							},
						},
						Name:    "malicious-package-in-range",
						Version: "1.0.1", // Matches malicious versions, will produce an issue.
						Locations: ftypes.Locations{
							{
								StartLine: 10, // Only the first line location is used.
							},
							{
								StartLine: 30,
							},
						},
					},
				},
			},
			{
				Target: "ExcludedGemfile.lock",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "gem",
							},
						},
						Name:    "malicious-package-in-range",
						Version: "1.2.3", // Matches malicious versions, would produce an issue but file is not in tool execution.
						Locations: ftypes.Locations{
							{
								StartLine: 30,
							},
						},
					},
				},
			},
			{
				Target: "package-lock.json",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "npm",
							},
						},
						Name:    "malicious-package-with-exact-version",
						Version: "3.2.1", // Matches malicious version, will produce an issue.
						Locations: ftypes.Locations{
							{
								StartLine: 20,
							},
						},
					},
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "npm",
							},
						},
						Name:    "malicious-pacakge-with-unsupported-ecosystem-versioning",
						Version: "1", // Unsupported ecosystem versioning, does not match.
					},
				},
			},
			{
				Target: "Pipfile.lock",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "pypi",
							},
						},
						Name:    "malicious-pacakge-with-supported-ecosystem-versioning",
						Version: "3", // Matches even though this package has ecosystem versioning
						Locations: ftypes.Locations{
							{
								StartLine: 30,
							},
						},
					},
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "pypi",
							},
						},
						Name: "non-malicious-package",
					},
				},
			},
			{
				Target: "pubspec.lock",
				Packages: []ftypes.Package{
					{
						Identifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type: "pub", // Unsupported ecosystem
							},
						},
					},
				},
			},
		},
	}
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{
				ID: ruleIDMaliciousPackages,
			},
		},
		Files: &[]string{
			"go.mod",
			"Cargo.lock",
			"Gemfile.lock",
			"package-lock.json",
			"Pipfile.lock",
		},
	}
	underTest := MaliciousPackagesScanner{index: index}

	// Act
	result := underTest.Scan(report, toolExecution)

	// Assert
	expectedIssues := []codacy.Result{
		codacy.Issue{
			File:      "Gemfile.lock",
			Line:      10,
			Message:   "Malicious code in malicious-package-in-range (rubygems) - malicious-package-in-range@1.0.1",
			PatternID: ruleIDMaliciousPackages,
			SourceID:  "MAL-in-range",
		},
		codacy.Issue{
			File:      "package-lock.json",
			Line:      20,
			Message:   "Malicious code in malicious-package-with-exact-version (npm) - malicious-package-with-exact-version@3.2.1",
			PatternID: ruleIDMaliciousPackages,
			SourceID:  "MAL-exact-version",
		},
		codacy.Issue{
			File:      "Pipfile.lock",
			Line:      30,
			Message:   "Malicious code in malicious-pacakge-with-supported-ecosystem-versioning (pypi) - malicious-pacakge-with-supported-ecosystem-versioning@3",
			PatternID: ruleIDMaliciousPackages,
			SourceID:  "MAL-supported-ecosystem-version",
		},
		codacy.FileError{
			File:    "Cargo.lock",
			Message: "Line numbers not supported",
		},
	}
	assert.ElementsMatch(t, expectedIssues, result)
}

func TestScan_PatternNotEnabled(t *testing.T) {
	// Arrange
	underTest := MaliciousPackagesScanner{}

	// Act
	result := underTest.Scan(ptypes.Report{}, codacy.ToolExecution{Patterns: &[]codacy.Pattern{}})

	// Assert
	assert.Empty(t, result)
}

func TestLoadIndex(t *testing.T) {
	// Arrange
	maliciousPackageIndexFileName := "malicious-package.json.gz"

	tmpDir := t.TempDir()
	f, err := os.CreateTemp(tmpDir, maliciousPackageIndexFileName)
	if err != nil {
		assert.FailNow(t, "Failed to create malicious package index", err.Error())
	}
	defer os.RemoveAll(tmpDir)
	defer f.Close()

	gz := gzip.NewWriter(f)
	_, err = gz.Write([]byte(
		`{
			"npm": {
				"malicious-package": [
					{
						"id": "MAL-2025-1",
						"summary": "Malicious code in malicious-package (npm)",
						"versions": ["1.2.3", "3.2.1"],
						"ranges": [
							{	
								"type": "SEMVER",
								"events": [
									{"introduced": "1"},
									{"fixed": "2"}
								]
							}
						]
					}
				]
			}
		}`,
	))
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}
	err = gz.Close()
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}

	expectedIndex := maliciousPackagesByEcosystemAndName{
		"npm": maliciousPackagesByName{
			"malicious-package": []maliciousPackage{
				{
					ID:       "MAL-2025-1",
					Summary:  "Malicious code in malicious-package (npm)",
					Versions: []string{"1.2.3", "3.2.1"},
					Ranges: []maliciousPackageRange{
						{
							Type: "SEMVER",
							Events: []maliciousPackageRangeEvent{
								{
									Introduced: "1",
								},
								{
									Fixed: "2",
								},
							},
						},
					},
				},
			},
		},
	}

	// Act
	result, err := loadIndex(f.Name())

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedIndex, result)
}

func TestLoadIndex_NotJSON(t *testing.T) {
	// Arrange
	maliciousPackageIndexFileName := "malicious-package.json.gz"

	tmpDir := t.TempDir()
	f, err := os.CreateTemp(tmpDir, maliciousPackageIndexFileName)
	if err != nil {
		assert.FailNow(t, "Failed to create malicious package index", err.Error())
	}
	defer os.RemoveAll(tmpDir)
	defer f.Close()

	gz := gzip.NewWriter(f)
	_, err = gz.Write([]byte("{"))
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}
	err = gz.Close()
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}

	// Act
	result, err := loadIndex(f.Name())

	// Assert
	assert.ErrorContains(t, err, "Failed to decode malicious package index")
	assert.Nil(t, result)
}

func TestLoadIndex_NotGz(t *testing.T) {
	// Arrange
	maliciousPackageIndexFileName := "malicious-package.json.gz"

	tmpDir := t.TempDir()
	f, err := os.CreateTemp(tmpDir, maliciousPackageIndexFileName)
	if err != nil {
		assert.FailNow(t, "Failed to create malicious package index", err.Error())
	}
	defer os.RemoveAll(tmpDir)
	defer f.Close()

	_, err = f.Write([]byte("{}"))
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}

	// Act
	result, err := loadIndex(f.Name())

	// Assert
	assert.ErrorContains(t, err, "Failed to read malicious package index")
	assert.Nil(t, result)
}

func TestLoadIndex_NotFound(t *testing.T) {
	// Act
	result, err := loadIndex("non-existent.json.gz")

	// Assert
	assert.ErrorContains(t, err, "Failed to open malicious package index")
	assert.Nil(t, result)
}

func TestSemverCompare(t *testing.T) {
	// Act
	result := semverCompare("1", "v2")

	// Assert
	assert.Equal(t, -1, result)
}

func TestOsvPackageEcosystem(t *testing.T) {
	// Arrange
	type testData struct {
		purlType                    string
		expectedOsvPackageEcosystem osvEcosystem
	}

	testSet := map[string]testData{
		"golang": {
			purlType:                    "golang",
			expectedOsvPackageEcosystem: golang,
		},
		"gem": {
			purlType:                    "gem",
			expectedOsvPackageEcosystem: rubygems,
		},
		"cargo": {
			purlType:                    "cargo",
			expectedOsvPackageEcosystem: cratesio,
		},
		"npm": {
			purlType:                    "npm",
			expectedOsvPackageEcosystem: npm,
		},
		"nuget": {
			purlType:                    "NuGet",
			expectedOsvPackageEcosystem: nuget,
		},
		"something else": {
			purlType:                    "something Else",
			expectedOsvPackageEcosystem: osvPackageEcosystem("something else"),
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			result := osvPackageEcosystem(testData.purlType)

			// Assert
			assert.Equal(t, testData.expectedOsvPackageEcosystem, result)
		})
	}
}

func TestMaliciousPackageMatchesVersion(t *testing.T) {
	type testData struct {
		mp             maliciousPackage
		version        string
		ecosystem      osvEcosystem
		expectedResult bool
	}

	testSet := map[string]testData{
		"matches exact version": {
			mp: maliciousPackage{
				Versions: []string{"1.2.3", "3.2.1"},
			},
			version:        "3.2.1",
			expectedResult: true,
		},
		"matches semver version range": {
			mp: maliciousPackage{
				Ranges: []maliciousPackageRange{
					{
						Type: "SEMVER",
						Events: []maliciousPackageRangeEvent{
							{Introduced: "0"},
						},
					},
				},
			},
			version:        "0.0.1",
			expectedResult: true,
		},
		"does not match ecosystem range, non-supported ecosystem": {
			mp: maliciousPackage{
				Ranges: []maliciousPackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []maliciousPackageRangeEvent{
							{Introduced: "0"},
						},
					},
				},
			},
			version:        "0.0.1",
			ecosystem:      rubygems,
			expectedResult: false,
		},
		"matche ecosystem range, supported ecosystem": {
			mp: maliciousPackage{
				Ranges: []maliciousPackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []maliciousPackageRangeEvent{
							{Introduced: "0"},
						},
					},
				},
			},
			version:        "0.0.1",
			ecosystem:      pypi,
			expectedResult: true,
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			result := testData.mp.matchesVersion(testData.version, testData.ecosystem)

			// Assert
			assert.Equal(t, testData.expectedResult, result)
		})
	}
}

func TestMaliciousPackageRangeMatchesVersion(t *testing.T) {
	type testData struct {
		mpRange        maliciousPackageRange
		version        string
		ecosystem      osvEcosystem
		expectedResult bool
	}

	testSet := map[string]testData{
		"SEMVER no matches": {
			mpRange: maliciousPackageRange{
				Type: "SEMVER",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "1.0.0-beta.1"},
					{LastAffected: "1.0.0-beta.3"},
				},
			},
			version:        "1.0.0-beta.4",
			expectedResult: false,
		},
		"SEMVER matches": {
			mpRange: maliciousPackageRange{
				Type: "SEMVER",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "3"},
					{LastAffected: "4"},
					{Introduced: "0"},
					{Fixed: "1"},
				},
			},
			version:        "4.0.0",
			expectedResult: true,
		},
		"non-supported ECOSYSTEM": {
			mpRange: maliciousPackageRange{
				Type: "ECOSYSTEM",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "0"},
				},
			},
			version:        "1",
			ecosystem:      cratesio,
			expectedResult: false,
		},
		"supported ECOSYSTEM matches": {
			mpRange: maliciousPackageRange{
				Type: "ECOSYSTEM",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "0"},
				},
			},
			version:        "1",
			ecosystem:      maven,
			expectedResult: true,
		},
		// See https://packaging.python.org/en/latest/discussions/versioning/
		"supported ECOSYSTEM false positive, epoch versioning": {
			mpRange: maliciousPackageRange{
				Type: "ECOSYSTEM",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "1!3.0.0"},
				},
			},
			version:        "1!2.0.0",
			ecosystem:      pypi,
			expectedResult: true, // This is a false positive due the conversion of versions to semver.
		},
		// See https://packaging.python.org/en/latest/discussions/versioning/
		"supported ECOSYSTEM false positive, post release versioning": {
			mpRange: maliciousPackageRange{
				Type: "ECOSYSTEM",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "1.2.3.post1"},
				},
			},
			version:        "1.2.3",
			ecosystem:      pypi,
			expectedResult: true, // This is a false positive due the conversion of versions to semver.
		},
		"supported ECOSYSTEM no matches": {
			mpRange: maliciousPackageRange{
				Type: "ECOSYSTEM",
				Events: []maliciousPackageRangeEvent{
					{Introduced: "2"},
				},
			},
			version:        "1",
			ecosystem:      pypi,
			expectedResult: false,
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			result := testData.mpRange.matchesVersion(testData.version, testData.ecosystem)

			// Assert
			assert.Equal(t, testData.expectedResult, result)
		})
	}
}

func TestMaliciousPackageRangeEventMatchesVersion(t *testing.T) {
	type testData struct {
		event          maliciousPackageRangeEvent
		version        string
		expectedResult bool
	}

	// Arrange
	testSet := map[string]testData{
		"matches introduced": {
			event: maliciousPackageRangeEvent{
				Introduced: "0",
			},
			version:        "0.0.1",
			expectedResult: true,
		},
		"does not match introduced": {
			event: maliciousPackageRangeEvent{
				Introduced: "1",
			},
			version:        "0.9.9",
			expectedResult: false,
		},
		"matches fixed": {
			event: maliciousPackageRangeEvent{
				Fixed: "0.0.2",
			},
			version:        "0.0.1",
			expectedResult: true,
		},
		"does not match fixed": {
			event: maliciousPackageRangeEvent{
				Fixed: "0.9.8",
			},
			version:        "0.9.9",
			expectedResult: false,
		},
		"matches last affected": {
			event: maliciousPackageRangeEvent{
				LastAffected: "3.2",
			},
			version:        "3.2.0",
			expectedResult: true,
		},
		"does not match last affected": {
			event: maliciousPackageRangeEvent{
				LastAffected: "3.2",
			},
			version:        "3.2.1",
			expectedResult: false,
		},
		"does not match empty": {
			event:          maliciousPackageRangeEvent{},
			version:        "0",
			expectedResult: false,
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			result := testData.event.matchesVersion(testData.version)

			// Assert
			assert.Equal(t, testData.expectedResult, result)
		})
	}
}
