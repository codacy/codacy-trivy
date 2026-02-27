package openssfdb

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildAggregatesEntries(t *testing.T) {
	t.Helper()

	builder := NewBuilder()
	fixedNow := time.Date(2025, time.January, 20, 12, 0, 0, 0, time.UTC)
	builder.now = func() time.Time { return fixedNow }

	ctx := context.Background()
	repoDir := filepath.Join("testdata", "repo")

	output, err := builder.Build(ctx, repoDir, "test-source")
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if output.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %s", output.SchemaVersion)
	}
	if !output.GeneratedAt.Equal(fixedNow) {
		t.Fatalf("generated timestamp mismatch, got %s", output.GeneratedAt.Format(time.RFC3339))
	}
	if output.Source != "test-source" {
		t.Fatalf("unexpected source recorded: %s", output.Source)
	}

	npmPackages, ok := output.Packages["npm"]
	if !ok {
		t.Fatalf("expected npm ecosystem")
	}
	npmEntry := npmPackages["pkg-one"]
	if len(npmEntry) != 1 {
		t.Fatalf("expected 1 entry for pkg-one, got %d", len(npmEntry))
	}
	entry := npmEntry[0]
	if entry.ID != "MAL-TEST-0001" {
		t.Errorf("unexpected ID: %s", entry.ID)
	}
	if entry.Package != "pkg-one" {
		t.Errorf("unexpected package name: %s", entry.Package)
	}
	if entry.Ecosystem != "npm" {
		t.Errorf("unexpected ecosystem: %s", entry.Ecosystem)
	}
	if len(entry.Versions) != 2 || entry.Versions[0] != "1.0.0" || entry.Versions[1] != "1.0.1" {
		t.Errorf("unexpected versions: %#v", entry.Versions)
	}
	if len(entry.Ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(entry.Ranges))
	}
	if len(entry.Ranges[0].Events) != 2 {
		t.Fatalf("expected 2 range events, got %d", len(entry.Ranges[0].Events))
	}
	if entry.Ranges[0].Events[0].Introduced != "0" {
		t.Errorf("unexpected introduced: %s", entry.Ranges[0].Events[0].Introduced)
	}
	if entry.Ranges[0].Events[1].Fixed != "1.0.2" {
		t.Errorf("unexpected fixed: %s", entry.Ranges[0].Events[1].Fixed)
	}
	if entry.Summary == "" || entry.Details == "" {
		t.Errorf("expected summary and details to be retained")
	}
	if len(entry.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(entry.References))
	}
	if len(entry.Aliases) != 1 || entry.Aliases[0] != "GHSA-1111-aaaa" {
		t.Errorf("expected aliases to be preserved, got %#v", entry.Aliases)
	}

	pypiPackages, ok := output.Packages["pypi"]
	if !ok {
		t.Fatalf("expected pypi ecosystem")
	}
	pypiEntry := pypiPackages["pkg-two"]
	if len(pypiEntry) != 1 {
		t.Fatalf("expected 1 entry for pkg-two, got %d", len(pypiEntry))
	}
	if pypiEntry[0].Ranges[0].Events[1].LastAffected != "1.3.4" {
		t.Errorf("expected last_affected to be retained, got %#v", pypiEntry[0].Ranges[0].Events)
	}
}

func TestWriteGzippedJSONCreatesReadablePayload(t *testing.T) {
	t.Helper()

	builder := NewBuilder()
	fixedNow := time.Date(2025, time.January, 20, 12, 0, 0, 0, time.UTC)
	builder.now = func() time.Time { return fixedNow }

	ctx := context.Background()
	repoDir := filepath.Join("testdata", "repo")

	output, err := builder.Build(ctx, repoDir, "test-source")
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "db", "openssf-malicious.json.gz")

	if err := WriteGzippedJSON(dest, output); err != nil {
		t.Fatalf("WriteGzippedJSON returned error: %v", err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("expected gzipped JSON to be written: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("expected gzipped JSON file to have content")
	}

	file, err := os.Open(dest)
	if err != nil {
		t.Fatalf("failed to open written file: %v", err)
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gz.Close()

	var decoded Output
	if err := json.NewDecoder(gz).Decode(&decoded); err != nil {
		t.Fatalf("failed to decode written JSON: %v", err)
	}

	if decoded.SchemaVersion != SchemaVersion {
		t.Errorf("schema version mismatch after round-trip: %s", decoded.SchemaVersion)
	}
	if _, ok := decoded.Packages["npm"]; !ok {
		t.Errorf("npm ecosystem missing after round-trip")
	}
	if _, ok := decoded.Packages["pypi"]; !ok {
		t.Errorf("pypi ecosystem missing after round-trip")
	}
}
