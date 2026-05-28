//go:generate go run go.uber.org/mock/mockgen -destination runner.mock.gen.go -package tool github.com/aquasecurity/trivy/pkg/commands/artifact Runner

package tool

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v8"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNew(t *testing.T) {
	// Arrange
	// Create an empty temporary file for the malicious packages index
	maliciousPackageIndexFileName := "malicious-package.json.gz"

	tmpDir := t.TempDir()
	f, err := os.CreateTemp(tmpDir, maliciousPackageIndexFileName)
	if err != nil {
		assert.FailNow(t, "Failed to create malicious package index", err.Error())
	}
	defer os.RemoveAll(tmpDir)
	defer f.Close()

	gz := gzip.NewWriter(f)
	_, err = gz.Write([]byte("{}"))
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}
	err = gz.Close()
	if err != nil {
		assert.FailNow(t, "Failed to write to malicious package index", err.Error())
	}

	// Act
	underTest, err := New(f.Name())

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, &defaultRunnerFactory{}, underTest.runnerFactory)
}

func TestNew_MaliciousPackageIndexFileNotFound(t *testing.T) {
	// Act
	underTest, err := New("non-existent-file.json.gz")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, underTest)
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
				ID: ruleIDVulnerabilityCritical,
			},
			{
				ID: ruleIDVulnerabilityHigh,
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
			OfflineScan:       true,
			Scanners:          ptypes.Scanners{ptypes.VulnerabilityScanner},
			Target:            srcDir,
			DetectionPriority: ftypes.PriorityComprehensive,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbtypes.SourceID{dbtypes.SourceID("auto")},
		},
	}

	report := ptypes.Report{
		ArtifactType: ftypes.TypeFilesystem,
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
					{
						Identifier: ftypes.PkgIdentifier{
							BOMRef: "no-purl",
							UID:    "no-purl",
							PURL:   nil,
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
					// To be skipped since it doesn't have a PURL
					{
						VulnerabilityID: "no PURL",
						Vulnerability: dbtypes.Vulnerability{
							Severity: "HIGH",
							Title:    "no PURL",
						},
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: nil,
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
		pkg1Chain := `[["type/@namespace/package-1@version+incompatible"]]`
		expectedIssues := []codacy.Issue{
			{
				File:        fileName,
				Line:        1,
				PatternID:   ruleIDVulnerabilityCritical,
				Message:     "Insecure dependency type/@namespace/package-1@version+incompatible (vuln id: vuln title) (update to vuln fixed)",
				SourceID:    "vuln id",
				ExtraFields: json.RawMessage(`{"CVE":"vuln id","dependenciesChains":` + pkg1Chain + `,"fixVersion":"vuln fixed"}`),
			},
			{
				File:        fileName,
				Line:        1,
				PatternID:   ruleIDVulnerabilityHigh,
				Message:     "Insecure dependency type/@namespace/package-1@version+incompatible (vuln id no fixed version: vuln no fixed version) (no fix available)",
				SourceID:    "vuln id no fixed version",
				ExtraFields: json.RawMessage(`{"CVE":"vuln id no fixed version","dependenciesChains":` + pkg1Chain + `,"fixVersion":""}`),
			},
			{
				File:      fileName,
				Line:      1,
				PatternID: ruleIDSecret,
				Message:   "Possible hardcoded secret: AWS Access Key ID",
				SourceID:  "aws-access-key-id",
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
		expectedBOM := cyclonedx.BOM{
			JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
			BOMFormat:    "CycloneDX",
			SpecVersion:  cyclonedx.SpecVersion1_6,
			SerialNumber: "urn:uuid:181e846e-fede-46b6-8be7-206a0f393caa", // different every run
			Version:      1,
			Metadata: &cyclonedx.Metadata{
				Timestamp: "2024-09-19T09:41:02.021Z", // different every run
				Tools: &cyclonedx.ToolsChoice{
					Components: &[]cyclonedx.Component{
						{
							Type: "application",
							Manufacturer: &cyclonedx.OrganizationalEntity{
								Name: "Aqua Security Software Ltd.",
							},
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
					BOMRef:     "no-purl",
					Type:       "library",
					Properties: &[]cyclonedx.Property{},
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
						"no-purl",
						"pkg:type/@namespace/package-1@version+incompatible",
						"pkg:type/@namespace/package-2@version+RC",
					},
				},
				{
					Ref:          "no-purl",
					Dependencies: &[]string{},
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
		}
		sboms := lo.Filter(results, func(result codacy.Result, _ int) bool {
			switch result.(type) {
			case codacy.SBOM:
				return true
			default:
				return false
			}
		})

		var obtainedBOM *cyclonedx.BOM
		err := json.Unmarshal([]byte(sboms[0].(codacy.SBOM).Sbom), &obtainedBOM)
		assert.NoError(t, err)

		// Set values that change on every run to known values.
		// This allows us to test the relationship between components.
		oldMetadataComponentBOMRef := obtainedBOM.Metadata.Component.BOMRef
		obtainedBOM.Metadata.Component.BOMRef = expectedMetadataComponentBOMRef
		// Components are always in declaration order, with the root component (created automatically) coming first
		cs := *obtainedBOM.Components
		oldRootComponentBOMRef := cs[0].BOMRef
		cs[0].BOMRef = expectedRootComponentBOMRef
		cs[0].Name = expectedRooComponentName
		// Dependencies are not always in order we must take care to change the correct value
		ds := *obtainedBOM.Dependencies
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
		assert.Equal(t, sboms[0].(codacy.SBOM).BomFormat, codacy.CycloneDXJSON)
		assert.Equal(t, sboms[0].(codacy.SBOM).SpecVersion, "1.6")
		assert.True(
			t,
			cmp.Equal(
				expectedBOM,
				*obtainedBOM,
				cmp.Options{
					// Ignore fields that change each run
					cmpopts.IgnoreFields(cyclonedx.BOM{}, "SerialNumber"),
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
				ID: ruleIDVulnerabilityHigh,
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
				ID: ruleIDVulnerabilityCritical,
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
			OfflineScan:       true,
			Scanners:          ptypes.Scanners{ptypes.VulnerabilityScanner},
			Target:            sourceDir,
			DetectionPriority: ftypes.PriorityComprehensive,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbtypes.SourceID{dbtypes.SourceID("auto")},
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
			expectedRuleID: ruleIDVulnerabilityHigh,
		},
		"critical": {
			trivySeverity:  "CrItIcAl",
			expectedRuleID: ruleIDVulnerabilityCritical,
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
		{ID: ruleIDVulnerabilityCritical},
		{ID: ruleIDVulnerabilityHigh},
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

func TestFallbackSearchForLineNumber_GoModStdlib(t *testing.T) {
	type testData struct {
		fileContents       string
		expectedLineNumber int
	}
	testSet := map[string]testData{
		"only toolchain directive": {
			fileContents:       "module abc\n\n\n toolchain go1.2.3",
			expectedLineNumber: 4,
		},
		"only go directive": {
			fileContents:       "module abc\n\n\n\n go 1.2.3",
			expectedLineNumber: 5,
		},
		"toolchain and go directives": {
			fileContents:       "module abc\n toolchain go1.21.4\ngo 1.2.3",
			expectedLineNumber: 2,
		},
		"go and toolchain directives": {
			fileContents:       "module abc\n go 1.21.4\ntoolchain go1.2.3",
			expectedLineNumber: 3,
		},
		"no directives": {
			fileContents:       "module abc",
			expectedLineNumber: 0,
		},
	}

	// Arrange
	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			srcDir, err := os.MkdirTemp("", "tool.TestFallbackSearchForLineNumber_GoModStdlib")
			if err != nil {
				assert.FailNow(t, "Failed to create tmp directory", err.Error())
			}
			defer os.RemoveAll(srcDir)

			f, err := os.Create(fmt.Sprintf("%s/go.mod", srcDir))
			if err != nil {
				assert.FailNow(t, "Failed to create tmp file", err.Error())
			}
			defer f.Close()

			if _, err := f.Write([]byte(testData.fileContents)); err != nil {
				assert.FailNow(t, "Failed to write to tmp file", err.Error())
			}

			fileName := filepath.Base(f.Name())

			// Act
			lineNumber := fallbackSearchForLineNumber(srcDir, fileName, "stdlib")

			// Assert
			assert.Equal(t, testData.expectedLineNumber, lineNumber)
		})
	}
}

func TestFallbackSearchForLineNumber_NonExistentFile(t *testing.T) {
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
		"semver with expected format (installed w/ v prefix)": {
			fixedVersion:         "1.2.3, 3.2.1, 1.2.5",
			installedVersion:     "v1.2.4",
			expectedFixedVersion: "1.2.5",
		},
		"semver with expected format (fixed w/ v prefix)": {
			fixedVersion:         "v1.2.3, v3.2.1, v1.2.5",
			installedVersion:     "1.2.4",
			expectedFixedVersion: "v1.2.5",
		},
		"semver with expected format (installed and fixed w/ v prefix)": {
			fixedVersion:         "v1.2.3, v3.2.1, v1.2.5",
			installedVersion:     "v1.2.4",
			expectedFixedVersion: "v1.2.5",
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

func makePkg(uid string, purl *packageurl.PackageURL, dependsOn ...string) ftypes.Package {
	return ftypes.Package{
		Identifier: ftypes.PkgIdentifier{
			UID:  uid,
			PURL: purl,
		},
		DependsOn: dependsOn,
	}
}

func newPURL(pkgType, namespace, name, version string) *packageurl.PackageURL {
	return packageurl.NewPackageURL(pkgType, namespace, name, version, nil, "")
}

func TestBuildDependencyChains(t *testing.T) {
	type testData struct {
		packages    []ftypes.Package
		targetPURL  string
		expected    [][]string
	}

	vulnPURL := newPURL("npm", "", "vuln-pkg", "1.0.0")
	parentPURL := newPURL("npm", "", "parent-pkg", "2.0.0")
	grandparentPURL := newPURL("npm", "", "grandparent-pkg", "3.0.0")
	sibling1PURL := newPURL("npm", "", "sibling-1", "1.0.0")
	sibling2PURL := newPURL("npm", "", "sibling-2", "1.0.0")

	vulnUID := vulnPURL.String()
	parentUID := parentPURL.String()
	grandparentUID := grandparentPURL.String()
	sibling1UID := sibling1PURL.String()
	sibling2UID := sibling2PURL.String()

	testSet := map[string]testData{
		"direct dependency — no parents, single-element chain": {
			packages: []ftypes.Package{
				makePkg(vulnUID, vulnPURL),
			},
			targetPURL: vulnUID,
			expected:   [][]string{{"npm/vuln-pkg@1.0.0"}},
		},
		"single transitive chain — one parent": {
			packages: []ftypes.Package{
				makePkg(vulnUID, vulnPURL),
				makePkg(parentUID, parentPURL, vulnUID),
			},
			targetPURL: vulnUID,
			expected:   [][]string{{"npm/parent-pkg@2.0.0", "npm/vuln-pkg@1.0.0"}},
		},
		"deep transitive chain — two ancestors": {
			packages: []ftypes.Package{
				makePkg(vulnUID, vulnPURL),
				makePkg(parentUID, parentPURL, vulnUID),
				makePkg(grandparentUID, grandparentPURL, parentUID),
			},
			targetPURL: vulnUID,
			expected:   [][]string{{"npm/grandparent-pkg@3.0.0", "npm/parent-pkg@2.0.0", "npm/vuln-pkg@1.0.0"}},
		},
		"multiple paths to root — two chains": {
			packages: []ftypes.Package{
				makePkg(vulnUID, vulnPURL),
				makePkg(sibling1UID, sibling1PURL, vulnUID),
				makePkg(sibling2UID, sibling2PURL, vulnUID),
			},
			targetPURL: vulnUID,
			expected: [][]string{
				{"npm/sibling-1@1.0.0", "npm/vuln-pkg@1.0.0"},
				{"npm/sibling-2@1.0.0", "npm/vuln-pkg@1.0.0"},
			},
		},
		"target PURL not found — returns nil": {
			packages: []ftypes.Package{
				makePkg(parentUID, parentPURL, vulnUID),
			},
			targetPURL: vulnUID,
			expected:   nil,
		},
		"package without PURL — falls back to UID as name": {
			packages: []ftypes.Package{
				makePkg(vulnUID, vulnPURL),
				makePkg("no-purl-root", nil, vulnUID),
			},
			targetPURL: vulnUID,
			expected:   [][]string{{"no-purl-root", "npm/vuln-pkg@1.0.0"}},
		},
		"max chains limit — stops at 10": {
			packages: func() []ftypes.Package {
				pkgs := []ftypes.Package{makePkg(vulnUID, vulnPURL)}
				for i := 0; i < 15; i++ {
					uid := fmt.Sprintf("root-%d", i)
					pkgs = append(pkgs, makePkg(uid, nil, vulnUID))
				}
				return pkgs
			}(),
			targetPURL: vulnUID,
			expected: func() [][]string {
				var chains [][]string
				for i := 0; i < maxDependencyChains; i++ {
					chains = append(chains, []string{fmt.Sprintf("root-%d", i), "npm/vuln-pkg@1.0.0"})
				}
				return chains
			}(),
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			result := buildDependencyChains(testData.targetPURL, testData.packages)
			assert.Equal(t, testData.expected, result)
		})
	}
}

func TestBuildDependencyChains_CycleTerminates(t *testing.T) {
	vulnPURL := newPURL("npm", "", "vuln-pkg", "1.0.0")
	sibling1PURL := newPURL("npm", "", "sibling-1", "1.0.0")
	sibling2PURL := newPURL("npm", "", "sibling-2", "1.0.0")
	vulnUID := vulnPURL.String()
	sibling1UID := sibling1PURL.String()
	sibling2UID := sibling2PURL.String()

	// sibling1 and sibling2 mutually depend on each other, both depend on vuln
	packages := []ftypes.Package{
		makePkg(vulnUID, vulnPURL),
		makePkg(sibling1UID, sibling1PURL, vulnUID, sibling2UID),
		makePkg(sibling2UID, sibling2PURL, vulnUID, sibling1UID),
	}

	result := buildDependencyChains(vulnUID, packages)

	// Cycle guard must prevent infinite loop; exactly 2 finite chains produced
	assert.Len(t, result, 2)
	for _, chain := range result {
		// Each chain must end with the vulnerable package
		assert.Equal(t, "npm/vuln-pkg@1.0.0", chain[len(chain)-1])
		// Chain is finite (cycle broken, so length <= 3 for this graph)
		assert.LessOrEqual(t, len(chain), 3)
	}
}

func TestBuildDependencyChains_ChainLengthTrimmed(t *testing.T) {
	// Build a linear chain 25 nodes deep: root -> n1 -> n2 -> ... -> vuln
	vulnPURL := newPURL("npm", "", "vuln-pkg", "1.0.0")
	vulnUID := vulnPURL.String()

	packages := []ftypes.Package{makePkg(vulnUID, vulnPURL)}
	prevUID := vulnUID
	for i := 0; i < 25; i++ {
		uid := fmt.Sprintf("ancestor-%d", i)
		packages = append(packages, makePkg(uid, nil, prevUID))
		prevUID = uid
	}

	result := buildDependencyChains(vulnUID, packages)
	if assert.Len(t, result, 1) {
		chain := result[0]
		assert.Len(t, chain, maxDependencyChainLen, "chain should be trimmed to maxDependencyChainLen")
		assert.Equal(t, "npm/vuln-pkg@1.0.0", chain[len(chain)-1], "vulnerable package must be last")
	}
}

func TestTrimChainTail(t *testing.T) {
	type testData struct {
		chain    []string
		max      int
		expected []string
	}

	testSet := map[string]testData{
		"chain shorter than max — returned unchanged": {
			chain:    []string{"a", "b", "c"},
			max:      5,
			expected: []string{"a", "b", "c"},
		},
		"chain equal to max — returned unchanged": {
			chain:    []string{"a", "b", "c"},
			max:      3,
			expected: []string{"a", "b", "c"},
		},
		"chain longer than max — tail kept": {
			chain:    []string{"a", "b", "c", "d", "e"},
			max:      3,
			expected: []string{"c", "d", "e"},
		},
	}

	for testName, testData := range testSet {
		t.Run(testName, func(t *testing.T) {
			result := trimChainTail(testData.chain, testData.max)
			assert.Equal(t, testData.expected, result)
		})
	}
}

type mockRunnerFactory struct {
	mockRunner artifact.Runner
}

func (f mockRunnerFactory) NewRunner(_ context.Context, _ flag.Options, _ artifact.TargetKind, _ ...artifact.RunnerOption) (artifact.Runner, error) {
	return f.mockRunner, nil
}

type errorRunnerFactory struct {
	err error
}

func (f errorRunnerFactory) NewRunner(_ context.Context, _ flag.Options, _ artifact.TargetKind, _ ...artifact.RunnerOption) (artifact.Runner, error) {
	return nil, f.err
}
