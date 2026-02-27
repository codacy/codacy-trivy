// Program eoltest runs the codacy-trivy tool against a directory with EOL patterns
// for local testing. EOL scan uses the xeol Go library (no xeol binary needed).
// Requires (for full scan) a valid malicious-packages index; uses an empty index if the default path is missing.
//
// Usage: go run ./cmd/eoltest -dir ./test-eol-project
package main

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/codacy/codacy-trivy/internal/tool"
)

func main() {
	dir := flag.String("dir", "", "Source directory to scan (e.g. test-eol-project)")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: eoltest -dir <path>")
		os.Exit(1)
	}
	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dir: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stat(absDir); err != nil {
		fmt.Fprintf(os.Stderr, "dir %s: %v\n", absDir, err)
		os.Exit(1)
	}
	indexPath, cleanup, err := resolveIndexPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	results, err := runEOLScan(context.Background(), absDir, indexPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	printEOLResults(results)
}

// resolveIndexPath returns the malicious-packages index path and a cleanup function.
// If the default path exists it is returned with a no-op cleanup; otherwise a temp empty index is created.
func resolveIndexPath() (path string, cleanup func(), err error) {
	path = tool.MaliciousPackagesIndexPath
	if _, err := os.Stat(path); err == nil {
		return path, func() {}, nil
	}
	f, err := os.CreateTemp("", "codacy-trivy-malicious-*.json.gz")
	if err != nil {
		return "", nil, fmt.Errorf("temp index: %w", err)
	}
	gw := gzip.NewWriter(f)
	_, _ = gw.Write([]byte("{}"))
	_ = gw.Close()
	_ = f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// runEOLScan runs the tool with EOL patterns only and returns all results.
func runEOLScan(ctx context.Context, dir, indexPath string) ([]codacy.Result, error) {
	trivy, err := tool.New(indexPath)
	if err != nil {
		return nil, fmt.Errorf("New: %w", err)
	}
	files := listFiles(dir)
	patterns := []codacy.Pattern{
		{ID: "eol_critical"},
		{ID: "eol_high"},
		{ID: "eol_medium"},
		{ID: "eol_minor"},
	}
	te := codacy.ToolExecution{SourceDir: dir, Patterns: &patterns, Files: &files}
	return trivy.Run(ctx, te)
}

// printEOLResults prints EOL issues and file errors from results, then a summary line.
func printEOLResults(results []codacy.Result) {
	var count int
	for _, r := range results {
		switch v := r.(type) {
		case codacy.Issue:
			if isEOL(v.PatternID) {
				count++
				fmt.Printf("%s:%d [%s] %s\n", v.File, v.Line, v.PatternID, v.Message)
			}
		case codacy.FileError:
			if v.File != "" {
				fmt.Fprintf(os.Stderr, "file error %s: %s\n", v.File, v.Message)
			}
		}
	}
	if count == 0 {
		fmt.Println("No EOL issues found. Ensure the project has EOL deps (e.g. npm install in test-eol-project) and XEOL_DB_CACHE_DIR is set or DB is in default cache.")
	} else {
		fmt.Printf("\nTotal EOL issues: %d\n", count)
	}
}

func listFiles(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		out = append(out, rel)
		return nil
	})
	return out
}

func isEOL(id string) bool {
	return id == "eol_critical" || id == "eol_high" || id == "eol_medium" || id == "eol_minor"
}
