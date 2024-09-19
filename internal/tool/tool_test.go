//go:generate go run go.uber.org/mock/mockgen -destination runner.mock.gen.go -package tool github.com/aquasecurity/trivy/pkg/commands/artifact Runner

package tool

import (
	"context"
	"os"
	"path/filepath"
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

	packageID1 := "package-1"
	packageID2 := "package-2"

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
						ID: packageID1,
						Locations: []ftypes.Location{
							{
								StartLine: 1,
							},
						},
					},
					{
						ID: packageID2,
					},
				},
				Vulnerabilities: []ptypes.DetectedVulnerability{
					// Will generate an issue
					{
						PkgID:           packageID1,
						VulnerabilityID: "vuln id",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "CRITICAL",
							Title:    "vuln title",
						},
						FixedVersion: "vuln fixed",
					},
					// Will generate an issue
					{
						PkgID:           packageID1,
						VulnerabilityID: "vuln id no fixed version",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "HIGH",
							Title:    "vuln no fixed version",
						},
					},
					// Will generate a file error
					{
						PkgID:           packageID2,
						VulnerabilityID: "no line",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "HIGH",
							Title:    "no line",
						},
						FixedVersion: "no line",
					},
					// Will be filtered out due to the severity
					{
						PkgID:           packageID1,
						VulnerabilityID: "filtered out by severity",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "LOW",
							Title:    "filtered out by severity",
						},
						FixedVersion: "filtered out by severity",
					},
				},
			},
			{
				Target: "will be filtered out",
				Vulnerabilities: []ptypes.DetectedVulnerability{
					// Will be filtered out because it belongs to a file that is not in the execution configuration
					{
						PkgID:           packageID1,
						VulnerabilityID: "unconfigured file",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "High",
							Title:    "unconfigured file",
						},
						FixedVersion: "no line",
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
				Message:   "Insecure dependency package-1 (vuln id: vuln title) (update to vuln fixed)",
			},
			{
				File:      fileName,
				Line:      1,
				PatternID: ruleIDVulnerability,
				Message:   "Insecure dependency package-1 (vuln id no fixed version: vuln no fixed version) (no fix available)",
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
								Type:  "application",
								Group: "aquasecurity",
								Name:  "trivy",
							},
						},
					},
					Component: &cyclonedx.Component{
						BOMRef: "b804b498-f626-41c5-a47f-45e1471acf33", // different every run
						Type:   "application",
						Properties: &[]cyclonedx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "0",
							},
						},
					},
				},
				Components: &[]cyclonedx.Component{},
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref:          "b804b498-f626-41c5-a47f-45e1471acf33",
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
					cmpopts.IgnoreFields(cyclonedx.Component{}, "BOMRef"),
					cmpopts.IgnoreFields(cyclonedx.Dependency{}, "Ref"),
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

func TestPkgId(t *testing.T) {
	// Arrange
	type testData struct {
		id            string
		name          string
		version       string
		expectedPkgID string
	}
	testSet := map[string]testData{
		"with ID": {
			id:            "id",
			expectedPkgID: "id",
		},
		"with name and version": {
			name:          "name",
			version:       "version",
			expectedPkgID: "name@version",
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			// Act
			id := pkgID(testData.id, testData.name, testData.version)

			// Assert
			assert.Equal(t, testData.expectedPkgID, id)
		})
	}
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
