package tool

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
)

func patchGoModFilesForStdlib(srcDir string, files []string) string {
	// Copy the files to a temporary directory because /src is read-only
	dstDir := "/tmp/src"
	if err := CopyFiles(files, srcDir, dstDir); err != nil {
		return srcDir
	}

	// Find and patch the go.mod files
	lo.ForEach(files, func(file string, _ int) {
		if strings.HasSuffix(file, "go.mod") {
			patchGoModFileForStdlib(filepath.Join(dstDir, file))
		}
	})

	return dstDir
}

// Find lines in go.mod files that specify the Go version and replace them with a require statement for the stdlib module.
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

// CopyFiles copies specific files from the source directory to the destination directory.
func CopyFiles(files []string, srcDir string, dstDir string) error {
	for _, file := range files {
		srcPath := filepath.Join(srcDir, file)
		dstPath := filepath.Join(dstDir, file)

		// Ensure the destination directory exists
		if err := os.MkdirAll(filepath.Dir(dstPath), os.ModePerm); err != nil {
			return err
		}

		// Copy the file
		if err := CopyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

// CopyFile copies a single file from src to dst.
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}
