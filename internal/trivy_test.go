package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrivyVersion(t *testing.T) {
	// Arrange
	expectedTrivyVersion := "X"
	os.Setenv("TRIVY_VERSION", expectedTrivyVersion)

	// Act
	trivyVersion := TrivyVersion()

	// Assert
	assert.Equal(t, expectedTrivyVersion, trivyVersion)
}

func TestTrivyVersion_Undefined(t *testing.T) {
	// Arrange
	expectedTrivyVersion := "dev"
	os.Unsetenv("TRIVY_VERSION")

	// Act
	trivyVersion := TrivyVersion()

	// Assert
	assert.Equal(t, expectedTrivyVersion, trivyVersion)
}
