package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	"github.com/stretchr/testify/assert"
)

func TestResolveIndexPathWithDefault_WhenPathExists(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "index.json.gz")
	f, err := os.Create(existing)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())

	path, cleanup, err := resolveIndexPathWithDefault(existing)
	assert.NoError(t, err)
	defer cleanup()
	assert.Equal(t, existing, path)
}

func TestResolveIndexPathWithDefault_WhenPathNotExists(t *testing.T) {
	path, cleanup, err := resolveIndexPathWithDefault(filepath.Join(t.TempDir(), "nonexistent.json.gz"))
	assert.NoError(t, err)
	defer cleanup()
	assert.NotEmpty(t, path)
	_, err = os.Stat(path)
	assert.NoError(t, err)
	cleanup()
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestPrintEOLResultsTo_Empty(t *testing.T) {
	var buf bytes.Buffer
	printEOLResultsTo(&buf, &buf, nil)
	assert.Contains(t, buf.String(), "No EOL issues found")
}

func TestPrintEOLResultsTo_OneIssue(t *testing.T) {
	var buf bytes.Buffer
	printEOLResultsTo(&buf, &buf, []codacy.Result{
		codacy.Issue{File: "go.mod", Line: 5, PatternID: "eol_critical", Message: "EOL pkg"},
	})
	out := buf.String()
	assert.Contains(t, out, "go.mod:5 [eol_critical] EOL pkg")
	assert.Contains(t, out, "Total EOL issues: 1")
}

func TestPrintEOLResultsTo_FileError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	printEOLResultsTo(&stdout, &stderr, []codacy.Result{
		codacy.FileError{File: "bad.txt", Message: "read failed"},
	})
	assert.Contains(t, stderr.String(), "file error bad.txt: read failed")
}

func TestIsEOL(t *testing.T) {
	assert.True(t, isEOL("eol_critical"))
	assert.True(t, isEOL("eol_high"))
	assert.True(t, isEOL("eol_medium"))
	assert.True(t, isEOL("eol_minor"))
	assert.False(t, isEOL("vulnerability_high"))
	assert.False(t, isEOL(""))
}
