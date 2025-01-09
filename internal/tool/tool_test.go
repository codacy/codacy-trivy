//go:generate go run go.uber.org/mock/mockgen -destination runner.mock.gen.go -package tool github.com/aquasecurity/trivy/pkg/commands/artifact Runner

package tool

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	fartifact "github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNew(t *testing.T) {
	// Act
	underTest := New()

	// Assert
	assert.Equal(t, &defaultRunnerFactory{}, underTest.runnerFactory)
}

func TestRun(t *testing.T) {
	// Arrange
	ctx := context.Background()
	ctrl := gomock.NewController(t)

	package1Purl := packageurl.NewPackageURL("type", "@namespace", "package-1", "version+incompatible", nil, "")
	package2Purl := packageurl.NewPackageURL("type", "@namespace", "package-2", "version+RC", nil, "")

	// Create a temporary file with a secret
	srcDir, err := os.MkdirTemp("", "")
	if err != nil {
		assert.FailNow(t, "Failed to create tmp directory", err.Error())
	}
	defer os.RemoveAll(srcDir)

	f, err := os.CreateTemp(srcDir, "file-")
	if err != nil {
		assert.FailNow(t, "Failed to create tmp file", err.Error())
	}
	defer f.Close()

	if _, err := f.Write([]byte("AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF")); err != nil {
		assert.FailNow(t, "Failed to write to tmp file", err.Error())
	}

	fileName := filepath.Base(f.Name())
	nonExistentFileName := "does-not-exist"

	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{
				ID: ruleIDSecret,
			},
			{
				ID: ruleIDVulnerability,
			},
			{
				ID: "unknown",
			},
		},
		Files:     &[]string{fileName, nonExistentFileName},
		SourceDir: srcDir,
	}

	config := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: cacheDir,
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes:         []string{ptypes.PkgTypeLibrary},
			PkgRelationships: ftypes.Relationships,
		},
		ReportOptions: flag.ReportOptions{
			ListAllPkgs: true,
		},
		ScanOptions: flag.ScanOptions{
			OfflineScan: true,
			Scanners:    ptypes.Scanners{ptypes.VulnerabilityScanner},
			Target:      srcDir,
		},
	}

	report := ptypes.Report{
		ArtifactType: fartifact.TypeFilesystem,
		Results: ptypes.Results{
			{
				Target: fileName,
				Packages: ftypes.Packages{
					{
						Locations: []ftypes.Location{
							{
								StartLine: 1,
							},
						},
						Identifier: ftypes.PkgIdentifier{
							BOMRef: package1Purl.String(),
							PURL:   package1Purl,
							UID:    package1Purl.String(),
						},
						Relationship: ftypes.RelationshipDirect,
					},
					{
						Identifier: ftypes.PkgIdentifier{
							BOMRef: package2Purl.String(),
							PURL:   package2Purl,
							UID:    package2Purl.String(),
						},
						Relationship: ftypes.RelationshipDirect,
					},
				},
				Class: ptypes.ClassLangPkg,
				Vulnerabilities: []ptypes.DetectedVulnerability{
					// Will generate an issue
					{
						VulnerabilityID: "vuln id",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "CRITICAL",
							Title:    "vuln title",
						},
						FixedVersion: "vuln fixed",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: package1Purl,
						},
					},
					// Will generate an issue
					{
						VulnerabilityID: "vuln id no fixed version",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "HIGH",
							Title:    "vuln no fixed version",
						},
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: package1Purl,
						},
					},
					// Will generate a file error
					{
						VulnerabilityID: "no line",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "HIGH",
							Title:    "no line",
						},
						FixedVersion: "no line",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: package2Purl,
						},
					},
					// Will be filtered out due to the severity
					{
						VulnerabilityID: "filtered out by severity",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "LOW",
							Title:    "filtered out by severity",
						},
						FixedVersion: "filtered out by severity",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: package1Purl,
						},
					},
				},
			},
			{
				Target: "will be filtered out",
				Vulnerabilities: []ptypes.DetectedVulnerability{
					// Will be filtered out because it belongs to a file that is not in the execution configuration
					{
						VulnerabilityID: "unconfigured file",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "High",
							Title:    "unconfigured file",
						},
						FixedVersion: "no line",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: package1Purl,
						},
					},
				},
			},
		},
	}

	mockRunner := NewMockRunner(ctrl)
	underTest := codacyTrivy{
		runnerFactory: mockRunnerFactory{mockRunner: mockRunner},
	}

	// Set expectations
	mockRunner.EXPECT().ScanFilesystem(
		gomock.Eq(ctx),
		gomock.Eq(config),
	).Return(report, nil).Times(1)
	mockRunner.EXPECT().Close(
		gomock.Eq(ctx),
	).Return(nil).Times(1)

	// Act
	results, err := underTest.Run(ctx, toolExecution)

	// Assert
	if assert.NoError(t, err) {
		expectedIssues := []codacy.Issue{
			{
				File:      fileName,
				Line:      1,
				PatternID: ruleIDVulnerability,
				Message:   "Insecure dependency type/@namespace/package-1@version+incompatible (vuln id: vuln title) (update to vuln fixed)",
			},
			{
				File:      fileName,
				Line:      1,
				PatternID: ruleIDVulnerability,
				Message:   "Insecure dependency type/@namespace/package-1@version+incompatible (vuln id no fixed version: vuln no fixed version) (no fix available)",
			},
			{
				File:      fileName,
				Line:      1,
				PatternID: ruleIDSecret,
				Message:   "Possible hardcoded secret: AWS Access Key ID",
			},
		}
		issues := lo.Filter(results, func(result codacy.Result, _ int) bool {
			switch result.(type) {
			case codacy.Issue:
				return true
			default:
				return false
			}
		})
		assert.ElementsMatch(t, expectedIssues, issues)

		expectedFileErrors := []codacy.FileError{
			{
				File:    fileName,
				Message: "Line numbers not supported",
			},
			{
				File:    nonExistentFileName,
				Message: "Failed to read source file",
			},
		}
		fileErrors := lo.Filter(results, func(result codacy.Result, _ int) bool {
			switch result.(type) {
			case codacy.FileError:
				return true
			default:
				return false
			}
		})
		assert.ElementsMatch(t, expectedFileErrors, fileErrors)

		expectedMetadataComponentBOMRef := "b804b498-f626-41c5-a47f-45e1471acf33"
		expectedRootComponentBOMRef := "d16d6083-4370-442f-a6ab-c5146a215dbe"
		expectedRooComponentName := "file-802713450"
		expectedSBOM := codacy.SBOM{
			BOM: cyclonedx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cyclonedx.SpecVersion(7),
				SerialNumber: "urn:uuid:181e846e-fede-46b6-8be7-206a0f393caa", // different every run
				Version:      1,
				Metadata: &cyclonedx.Metadata{
					Timestamp: "2024-09-19T09:41:02.021Z", // different every run
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type:    "application",
								Group:   "aquasecurity",
								Name:    "trivy",
								Version: "dev",
							},
						},
					},
					Component: &cyclonedx.Component{
						BOMRef: expectedMetadataComponentBOMRef,
						Type:   "application",
						Properties: &[]cyclonedx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "0",
							},
						},
					},
				},
				Components: &[]cyclonedx.Component{
					{
						BOMRef: expectedRootComponentBOMRef,
						Type:   "application",
						Name:   "file-802713450",
						Properties: &[]cyclonedx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name: "aquasecurity:trivy:Type",
							},
						},
					},
					{
						BOMRef:     "pkg:type/@namespace/package-1@version+incompatible",
						Type:       "library",
						Properties: &[]cyclonedx.Property{},
						PackageURL: "pkg:type/@namespace/package-1@version+incompatible",
						Version:    "version+incompatible",
					},
					{
						BOMRef:     "pkg:type/@namespace/package-2@version+RC",
						Type:       "library",
						Properties: &[]cyclonedx.Property{},
						PackageURL: "pkg:type/@namespace/package-2@version+RC",
						Version:    "version+RC",
					},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref: expectedMetadataComponentBOMRef,
						Dependencies: &[]string{
							expectedRootComponentBOMRef,
						},
					},
					{
						Ref: expectedRootComponentBOMRef,
						Dependencies: &[]string{
							"pkg:type/@namespace/package-1@version+incompatible",
							"pkg:type/@namespace/package-2@version+RC",
						},
					},
					{
						Ref:          "pkg:type/@namespace/package-1@version+incompatible",
						Dependencies: &[]string{},
					},
					{
						Ref:          "pkg:type/@namespace/package-2@version+RC",
						Dependencies: &[]string{},
					},
				},
				Vulnerabilities: &[]cyclonedx.Vulnerability{},
			},
		}
		sboms := lo.Filter(results, func(result codacy.Result, _ int) bool {
			switch result.(type) {
			case codacy.SBOM:
				return true
			default:
				return false
			}
		})

		// Set values that change on every run to known values.
		// This allows us to test the relationship between components.
		oldMetadataComponentBOMRef := sboms[0].(codacy.SBOM).Metadata.Component.BOMRef
		sboms[0].(codacy.SBOM).Metadata.Component.BOMRef = expectedMetadataComponentBOMRef
		// Components are always in declaration order, with the root component (created automatically) coming first
		cs := *sboms[0].(codacy.SBOM).Components
		oldRootComponentBOMRef := cs[0].BOMRef
		cs[0].BOMRef = expectedRootComponentBOMRef
		cs[0].Name = expectedRooComponentName
		// Dependencies are not always in order we must take care to change the correct value
		ds := *sboms[0].(codacy.SBOM).Dependencies
		for i, d := range ds {
			if d.Ref == oldMetadataComponentBOMRef {
				ds[i].Ref = expectedMetadataComponentBOMRef
				ds[i].Dependencies = &[]string{expectedRootComponentBOMRef}
			}
			if d.Ref == oldRootComponentBOMRef {
				ds[i].Ref = expectedRootComponentBOMRef
			}
		}
		// Ensure dependencies array is as we expect it, otherwise comparison fails
		slices.SortFunc(ds, func(a cyclonedx.Dependency, b cyclonedx.Dependency) int {
			return strings.Compare(a.Ref, b.Ref)
		})

		// Only one SBOM result is produced
		assert.Len(t, sboms, 1)
		assert.True(
			t,
			cmp.Equal(
				expectedSBOM,
				sboms[0],
				cmp.Options{
					// Ignore fields that change each run
					cmpopts.IgnoreFields(codacy.SBOM{}, "SerialNumber"),
					cmpopts.IgnoreFields(cyclonedx.Metadata{}, "Timestamp"),
				},
			),
		)
	}
}

func TestRunInvalidExecutionConfiguration(t *testing.T) {
	// Arrage
	underTest := codacyTrivy{}

	// Act
	results, err := underTest.Run(context.Background(), codacy.ToolExecution{})

	// Assert
	expectedErr := &ToolError{msg: "Failed to configure Codacy Trivy: no patterns configured"}
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, results)
}

func TestRunNewRunnerError(t *testing.T) {
	// Arrange
	file1 := "file-1"
	file2 := "file-2"

	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{
				ID: ruleIDVulnerability,
			},
		},
		Files: &[]string{file1, file2},
	}

	underTest := codacyTrivy{
		runnerFactory: errorRunnerFactory{err: assert.AnError},
	}

	// Act
	issues, err := underTest.Run(context.Background(), toolExecution)

	// Assert
	if assert.Error(t, err) {
		assert.Equal(t, assert.AnError, err)
		assert.Nil(t, issues)
	}
}

func TestRunScanFilesystemError(t *testing.T) {
	// Arrange
	ctx := context.Background()
	ctrl := gomock.NewController(t)

	file1 := "file-1"
	file2 := "file-2"

	sourceDir := "src"
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{
				ID: ruleIDSecret,
			},
			{
				ID: ruleIDVulnerability,
			},
		},
		SourceDir: sourceDir,
		Files:     &[]string{file1, file2},
	}

	config := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: cacheDir,
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes:         []string{ptypes.PkgTypeLibrary},
			PkgRelationships: ftypes.Relationships,
		},
		ReportOptions: flag.ReportOptions{
			ListAllPkgs: true,
		},
		ScanOptions: flag.ScanOptions{
			OfflineScan: true,
			Scanners:    ptypes.Scanners{ptypes.VulnerabilityScanner},
			Target:      sourceDir,
		},
	}

	mockRunner := NewMockRunner(ctrl)
	underTest := codacyTrivy{
		runnerFactory: mockRunnerFactory{mockRunner: mockRunner},
	}

	// Set expectations
	mockRunner.EXPECT().ScanFilesystem(
		gomock.Eq(ctx),
		gomock.Eq(config),
	).Return(ptypes.Report{}, assert.AnError).Times(1)
	mockRunner.EXPECT().Close(
		gomock.Eq(ctx),
	).Return(nil).Times(1)

	// Act
	issues, err := underTest.Run(ctx, toolExecution)

	// Assert
	if assert.Error(t, err) {
		expectedError := &ToolError{msg: "Failed to run Codacy Trivy", w: assert.AnError}
		assert.Equal(t, expectedError, err)
		assert.Nil(t, issues)
	}
}

func TestRunVulnerabilityScanningNotEnabled(t *testing.T) {
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{{ID: ruleIDSecret}},
	}
	underTest := codacyTrivy{}

	// Act
	results, err := underTest.getVulnerabilities(context.Background(), ptypes.Report{}, toolExecution)

	// Assert
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestRunSecretScanningNotEnabled(t *testing.T) {
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{{ID: ruleIDVulnerabilityMedium}},
	}
	underTest := codacyTrivy{}

	// Act
	results := underTest.runSecretScanning(toolExecution)

	// Assert
	assert.Empty(t, results)
}

func TestValidateExecutionConfiguration(t *testing.T) {
	// Arrange
	type testData struct {
		executionConfiguration codacy.ToolExecution
		errMsg                 string
	}
	testSet := map[string]testData{
		"no patterns": {
			executionConfiguration: codacy.ToolExecution{},
			errMsg:                 "Failed to configure Codacy Trivy: no patterns configured",
		},
		"unknown patterns": {
			executionConfiguration: codacy.ToolExecution{
				Patterns: &[]codacy.Pattern{
					{
						ID: "unknown",
					},
				},
			},
			errMsg: "Failed to configure Codacy Trivy: configured patterns don't match existing rules (provided [unknown])",
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			err := validateExecutionConfiguration(testData.executionConfiguration)

			// Assert
			expectedErr := &ToolError{msg: testData.errMsg}
			assert.Equal(t, expectedErr, err)
		})
	}
}

func TestGetRuleIdFromTrivySeverity(t *testing.T) {
	// Arrange
	type testData struct {
		trivySeverity  string
		expectedRuleID string
		expectedErr    error
	}

	testSet := map[string]testData{
		"low": {
			trivySeverity:  "LoW",
			expectedRuleID: ruleIDVulnerabilityMinor,
		},
		"medium": {
			trivySeverity:  "medium",
			expectedRuleID: ruleIDVulnerabilityMedium,
		},
		"high": {
			trivySeverity:  "hiGh",
			expectedRuleID: ruleIDVulnerability,
		},
		"critical": {
			trivySeverity:  "CrItIcAl",
			expectedRuleID: ruleIDVulnerability,
		},
		"unknown": {
			trivySeverity: "unknown",
			expectedErr:   &ToolError{msg: "Failed to run Codacy Trivy: unexpected Trivy severity unknown"},
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			ruleID, err := getRuleIDFromTrivySeverity(testData.trivySeverity)

			// Assert
			assert.Equal(t, testData.expectedRuleID, ruleID)
			assert.Equal(t, testData.expectedErr, err)
		})
	}
}

func TestGetTrivySeveritiesFromPatterns(t *testing.T) {
	// Assert
	patterns := []codacy.Pattern{
		{ID: ruleIDVulnerability},
		{ID: ruleIDVulnerabilityMedium},
		{ID: ruleIDVulnerabilityMinor},
		{ID: ruleIDSecret},
		{ID: "Unknown"},
	}

	// Act
	result := getTrivySeveritiesFromPatterns(patterns)

	// Assert
	expectedSeverities := []dbtypes.Severity{
		dbtypes.SeverityCritical,
		dbtypes.SeverityHigh,
		dbtypes.SeverityMedium,
		dbtypes.SeverityLow,
	}
	assert.ElementsMatch(t, expectedSeverities, result)
}

func TestFallbackSearchForLineNumber(t *testing.T) {
	type testData struct {
		pkgName            string
		expectedLineNumber int
	}
	testSet := map[string]testData{
		"pkgName found": {
			pkgName:            "pkgName",
			expectedLineNumber: 2,
		},
		"pkgName not found": {
			pkgName:            "not found",
			expectedLineNumber: 0,
		},
	}

	// Arrange
	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			srcDir, err := os.MkdirTemp("", "tool.TestFallbackSearchForLineNumber")
			if err != nil {
				assert.FailNow(t, "Failed to create tmp directory", err.Error())
			}
			defer os.RemoveAll(srcDir)

			f, err := os.CreateTemp(srcDir, "file-")
			if err != nil {
				assert.FailNow(t, "Failed to create tmp file", err.Error())
			}
			defer f.Close()

			if _, err := f.Write([]byte("something else\npkgName")); err != nil {
				assert.FailNow(t, "Failed to write to tmp file", err.Error())
			}

			fileName := filepath.Base(f.Name())

			// Act
			lineNumber := fallbackSearchForLineNumber(srcDir, fileName, testData.pkgName)

			// Assert
			assert.Equal(t, testData.expectedLineNumber, lineNumber)
		})
	}
}

func TestFallbackSearchForLineNumber_NonExistenFile(t *testing.T) {
	// Act
	lineNumber := fallbackSearchForLineNumber(".", "non-existent", "not used")

	// Assert
	expectedLineNumber := 0
	assert.Equal(t, expectedLineNumber, lineNumber)
}

func TestFindLeastDisruptiveFixedVerstion(t *testing.T) {
	type testData struct {
		fixedVersion         string
		installedVersion     string
		expectedFixedVersion string
	}

	testSet := map[string]testData{
		"semver with expected format": {
			fixedVersion:         "1.2.3, 3.2.1, 1.2.5",
			installedVersion:     "1.2.4",
			expectedFixedVersion: "1.2.5",
		},
		"not semver with expected format": {
			fixedVersion:         "vê um três, vê dois um",
			installedVersion:     "installed version",
			expectedFixedVersion: "vê um três, vê dois um",
		},
		"semver without expected format": {
			fixedVersion:         "1.2.3 ~> 3.2.1 ~> 1.2.5",
			installedVersion:     "1.2.4",
			expectedFixedVersion: "1.2.3 ~> 3.2.1 ~> 1.2.5",
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			fixedVersion := findLeastDisruptiveFixedVersion(
				ptypes.DetectedVulnerability{
					FixedVersion:     testData.fixedVersion,
					InstalledVersion: testData.installedVersion,
				},
			)

			// Assert
			assert.Equal(t, testData.expectedFixedVersion, fixedVersion)
		})
	}
}

func TestPurlPrettyPrint(t *testing.T) {
	// Arrange
	purl := packageurl.NewPackageURL("type", "namespace", "name", "1.2.0+incompatible", nil, "")

	// Act
	ppp := purlPrettyPrint(*purl)

	// Assert
	assert.Equal(t, "type/namespace/name@1.2.0+incompatible", ppp)
}

type mockRunnerFactory struct {
	mockRunner artifact.Runner
}

func (f mockRunnerFactory) NewRunner(_ context.Context, _ flag.Options) (artifact.Runner, error) {
	return f.mockRunner, nil
}

type errorRunnerFactory struct {
	err error
}

func (f errorRunnerFactory) NewRunner(_ context.Context, _ flag.Options) (artifact.Runner, error) {
	return nil, f.err
}
