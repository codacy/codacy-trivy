package tool

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
)

// RunnerFactory can create new Trivy runners.
type RunnerFactory interface {
	NewRunner(ctx context.Context, config flag.Options) (artifact.Runner, error)
}

type defaultRunnerFactory struct{}

func (f defaultRunnerFactory) NewRunner(ctx context.Context, config flag.Options) (artifact.Runner, error) {
	runner, err := artifact.NewRunner(ctx, config)
	if err != nil {
		return nil, &ToolError{msg: "Failed to initialize Codacy Trivy", w: err}
	}
	return runner, nil
}
