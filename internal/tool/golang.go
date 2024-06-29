package tool

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
)

func patchGoModFilesForStdlib(dir string, files []string) {
	lo.ForEach(files, func(file string, _ int) {
		if strings.HasSuffix(file, "go.mod") {
			patchGoModFileForStdlib(filepath.Join(dir, file))
		}
	})
}

func patchGoModFileForStdlib(filename string) {
	tempFilename := filename + ".tmp"

	// Open the original file for reading
	inputFile, err := os.Open(filename)
	if err != nil {
		return
	}
	defer inputFile.Close()

	// Create a temporary file for writing
	tempFile, err := os.Create(tempFilename)
	if err != nil {
		return
	}
	defer tempFile.Close()

	scanner := bufio.NewScanner(inputFile)
	writer := bufio.NewWriter(tempFile)

	// Process the file line by line
	for scanner.Scan() {
		line := scanner.Text()
		// Find go version statement
		if strings.HasPrefix(line, "go ") {
			version := strings.TrimPrefix(line, "go ")
			line = "require stdlib v" + version
		}
		// Find toolchain statement
		if strings.HasPrefix(line, "toolchain go") {
			version := strings.TrimPrefix(line, "toolchain go")
			line = "require stdlib v" + version
		}

		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		return
	}

	// Flush the writer
	if err := writer.Flush(); err != nil {
		return
	}

	// Close both files
	inputFile.Close()
	tempFile.Close()

	// Replace the original file with the temporary file
	if err := os.Rename(tempFilename, filename); err != nil {
		return
	}
}
