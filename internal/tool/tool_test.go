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
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
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

	sourceDir := "src"
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
		Files:     &[]string{file1, file2},
		SourceDir: sourceDir,
	}

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
			Scanners:    types.Scanners{types.VulnerabilityScanner},
			Target:      sourceDir,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: []types.VulnType{types.VulnTypeLibrary},
		},
	}

	report := types.Report{
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
					{
						PkgID:           "packageID10",
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
				Secrets: []types.DetectedSecret{
					{
						StartLine: 2,
						Title:     "secret title",
					},
				},
				Vulnerabilities: []types.DetectedVulnerability{
					{
						PkgID:           "packageID10",
						VulnerabilityID: "no line",
						Vulnerability: dbtypes.Vulnerability{
							Title: "no line",
						},
						FixedVersion: "no line",
					},
				},
			},
			{
				Target: "file-3",
				Secrets: []types.DetectedSecret{
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
	).Return(report, nil).Times(1)
	mockRunner.EXPECT().Close(
		gomock.Eq(ctx),
	).Return(nil).Times(1)

	// Act
	results, err := underTest.Run(ctx, toolExecution)

	// Assert
	if assert.NoError(t, err) {
		expectedResults := []codacy.Result{
			codacy.Issue{
				File:      file1,
				Line:      1,
				PatternID: ruleIDVulnerability,
				Message:   "Insecure dependency package-1 (vuln id: vuln title) (update to vuln fixed)",
			},
			codacy.FileError{
				File:    file1,
				Message: "Line numbers not supported",
			},
			codacy.FileError{
				File:    file2,
				Message: "Line numbers not supported",
			},
			codacy.FileError{
				File:    file1,
				Message: "Failed to read source file",
			},
			codacy.FileError{
				File:    file2,
				Message: "Failed to read source file",
			},
		}
		assert.ElementsMatch(t, expectedResults, results)
	}
}

func TestRunNoPatterns(t *testing.T) {
	// Arrange
	underTest := codacyTrivy{}

	// Act
	results, err := underTest.Run(context.Background(), codacy.ToolExecution{})

	// Assert
	if assert.NoError(t, err) {
		assert.Empty(t, results)
	}
}

func TestRunConfigurationError(t *testing.T) {
	// Arrange
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{
				ID: "unknown",
			},
		},
	}

	underTest := codacyTrivy{}

	// Act
	config, err := underTest.Run(context.Background(), toolExecution)

	// Assert
	if assert.Error(t, err) {
		expectedError := &ToolError{msg: "Failed to configure Codacy Trivy: provided patterns don't match existing rules"}
		assert.Equal(t, expectedError, err)
		assert.Nil(t, config)
	}
}

func TestRunNewRunnerError(t *testing.T) {
	// Arrange
	toolExecution := codacy.ToolExecution{
		Patterns: &[]codacy.Pattern{
			{
				ID: ruleIDVulnerability,
			},
		},
		Files: &[]string{},
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
	}

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
			Scanners:    types.Scanners{types.VulnerabilityScanner},
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
	issues, err := underTest.Run(ctx, toolExecution)

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
