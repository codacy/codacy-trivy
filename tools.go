//go:build tools

package main

import (
	_ "go.uber.org/mock/mockgen" // Tool dependency for mock generation.
)

// This file helps us declare dependencies on tools to generate code
// or libraries that generated code depends on.
// These dependencies will not be deleted by tidying the module.
// Furthermore, the use of the build constraint ensures the file
// is not compiled into the binary unless the `tools` flag is specified.
// For more info, see: https://marcofranssen.nl/manage-go-tools-via-go-modules
