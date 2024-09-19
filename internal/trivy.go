package internal

import "os"

// TrivyVersion returns the Trivy version being used by this tool.
func TrivyVersion() string {
	trivyVersion, ok := os.LookupEnv("TRIVY_VERSION")
	if !ok {
		return "dev"
	}
	return trivyVersion
}
