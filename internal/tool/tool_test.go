//go:generate go run go.uber.org/mock/mockgen -destination runner.mock.gen.go -package tool github.com/aquasecurity/trivy/pkg/commands/artifact Runner

package tool

import (
	"context"
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v5"
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

	file1 := "file-1"
	file2 := "file-2"

	packageID1 := "package-1"
	packageID2 := "package-2"

	tool := codacy.Tool{
		Patterns: []codacy.Pattern{
			{
				PatternID: ruleIDSecret,
			},
			{
				PatternID: ruleIDVulnerability,
			},
			{
				PatternID: "unknown",
			},
		},
		Files: []string{file1, file2},
	}
	sourceDir := "src"

	config := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: cacheDir,
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		ReportOptions: flag.ReportOptions{
			ListAllPkgs: true,
		},
		ScanOptions: flag.ScanOptions{
			OfflineScan: true,
			Scanners:    types.Scanners{types.SecretScanner, types.VulnerabilityScanner},
			Target:      sourceDir,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: []types.VulnType{types.VulnTypeLibrary},
		},
	}

	results := types.Report{
		Results: types.Results{
			{
				Target: file1,
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
				Vulnerabilities: []types.DetectedVulnerability{
					{
						PkgID:           packageID1,
						VulnerabilityID: "vuln id",
						Vulnerability: dbtypes.Vulnerability{
							Title: "vuln title",
						},
						FixedVersion: "vuln fixed",
					},
					{
						PkgID:           packageID2,
						VulnerabilityID: "no line",
						Vulnerability: dbtypes.Vulnerability{
							Title: "no line",
						},
						FixedVersion: "no line",
					},
				},
			},
			{
				Target: file2,
				Secrets: []ftypes.SecretFinding{
					{
						StartLine: 2,
						Title:     "secret title",
					},
				},
			},
			{
				Target: "file-3",
				Secrets: []ftypes.SecretFinding{
					{
						StartLine: 10,
						Title:     "unkown file",
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
	).Return(results, nil).Times(1)
	mockRunner.EXPECT().Close(
		gomock.Eq(ctx),
	).Return(nil).Times(1)

	// Act
	issues, err := underTest.Run(tool, sourceDir)

	// Assert
	if assert.NoError(t, err) {
		expectedIssues := []codacy.Issue{
			{
				File:      file1,
				Line:      1,
				PatternID: ruleIDVulnerability,
				Message:   "Insecure dependency package-1 (vuln id: vuln title) (update to vuln fixed)",
			},
			{
				File:      file2,
				Line:      2,
				PatternID: ruleIDSecret,
				Message:   "Possible hardcoded secret: secret title",
			},
		}
		assert.ElementsMatch(t, expectedIssues, issues)
	}
}

func TestRunNoPatterns(t *testing.T) {
	// Arrange
	underTest := codacyTrivy{}

	// Act
	issues, err := underTest.Run(codacy.Tool{}, "not-used")

	// Assert
	if assert.NoError(t, err) {
		assert.Empty(t, issues)
	}
}

func TestRunConfigurationError(t *testing.T) {
	// Arrange
	tool := codacy.Tool{
		Patterns: []codacy.Pattern{
			{
				PatternID: "unknown",
			},
		},
	}

	underTest := codacyTrivy{}

	// Act
	config, err := underTest.Run(tool, "not-used")

	// Assert
	if assert.Error(t, err) {
		expectedError := &ToolError{msg: "Failed to configure Codacy Trivy: provided patterns don't match existing rules"}
		assert.Equal(t, expectedError, err)
		assert.Nil(t, config)
	}
}

func TestRunNewRunnerError(t *testing.T) {
	// Arrange
	tool := codacy.Tool{
		Patterns: []codacy.Pattern{
			{
				PatternID: ruleIDSecret,
			},
		},
	}

	underTest := codacyTrivy{
		runnerFactory: errorRunnerFactory{err: assert.AnError},
	}

	// Act
	issues, err := underTest.Run(tool, "not-used")

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

	tool := codacy.Tool{
		Patterns: []codacy.Pattern{
			{
				PatternID: ruleIDSecret,
			},
			{
				PatternID: ruleIDVulnerability,
			},
		},
	}
	sourceDir := "src"

	config := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: cacheDir,
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		ReportOptions: flag.ReportOptions{
			ListAllPkgs: true,
		},
		ScanOptions: flag.ScanOptions{
			OfflineScan: true,
			Scanners:    types.Scanners{types.SecretScanner, types.VulnerabilityScanner},
			Target:      sourceDir,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: []types.VulnType{types.VulnTypeLibrary},
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
	).Return(types.Report{}, assert.AnError).Times(1)
	mockRunner.EXPECT().Close(
		gomock.Eq(ctx),
	).Return(nil).Times(1)

	// Act
	issues, err := underTest.Run(tool, sourceDir)

	// Assert
	if assert.Error(t, err) {
		expectedError := &ToolError{msg: "Failed to run Codacy Trivy", w: assert.AnError}
		assert.Equal(t, expectedError, err)
		assert.Nil(t, issues)
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
