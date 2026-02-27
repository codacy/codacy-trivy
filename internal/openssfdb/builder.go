package openssfdb

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// SchemaVersion defines the JSON schema version emitted for the packaged OpenSSF data.
	SchemaVersion = "1.0.0"
)

// Builder produces a compact representation of the OpenSSF malicious packages database.
type Builder struct {
	now func() time.Time
}

// Output describes the JSON payload persisted for consumption at runtime.
type Output struct {
	SchemaVersion string                         `json:"schema_version"`
	GeneratedAt   time.Time                      `json:"generated_at"`
	Source        string                         `json:"source"`
	Packages      map[string]map[string][]*Entry `json:"packages"`
}

// Entry contains the reduced malicious package metadata retained from the upstream OSV record.
type Entry struct {
	ID         string      `json:"id"`
	Ecosystem  string      `json:"ecosystem"`
	Package    string      `json:"package"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Versions   []string    `json:"versions,omitempty"`
	Ranges     []Range     `json:"ranges,omitempty"`
	References []Reference `json:"references,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Published  string      `json:"published,omitempty"`
	Modified   string      `json:"modified,omitempty"`
}

// Range models the OSV affected range information we keep for version matching.
type Range struct {
	Type   string       `json:"type"`
	Events []RangeEvent `json:"events,omitempty"`
}

// RangeEvent captures the supported OSV range event attributes.
type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference contains a pointer to additional upstream context for a malicious entry.
type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// NewBuilder returns a Builder instance configured for production use.
func NewBuilder() *Builder {
	return &Builder{
		now: time.Now,
	}
}

// parseOSVFile reads and decodes one OSV JSON file into a rawRecord.
func parseOSVFile(path string) (*rawRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var raw rawRecord
	if err := json.NewDecoder(file).Decode(&raw); err != nil {
		return nil, err
	}
	raw.trim()
	return &raw, nil
}

// aggregateRawInto merges a raw OSV record into the output package map.
func aggregateRawInto(out *Output, raw *rawRecord) {
	for _, affected := range raw.Affected {
		ecosystem := normalizeEcosystem(affected.Package.Ecosystem)
		if ecosystem == "" || affected.Package.Name == "" {
			continue
		}
		name := strings.ToLower(affected.Package.Name)
		entry := &Entry{
			ID:         raw.ID,
			Ecosystem:  ecosystem,
			Package:    affected.Package.Name,
			Summary:    raw.Summary,
			Details:    raw.Details,
			Versions:   cloneAndSort(affected.Versions),
			Ranges:     cloneRanges(affected.Ranges),
			References: cloneReferences(raw.References),
			Aliases:    cloneStrings(raw.Aliases),
			Published:  raw.Published,
			Modified:   raw.Modified,
		}
		if _, ok := out.Packages[ecosystem]; !ok {
			out.Packages[ecosystem] = make(map[string][]*Entry)
		}
		out.Packages[ecosystem][name] = append(out.Packages[ecosystem][name], entry)
	}
}

// Build walks the provided OpenSSF repository directory and emits an aggregated Output.
// The source parameter is used to document where the data originated from.
func (b *Builder) Build(ctx context.Context, repoDir, source string) (*Output, error) {
	if repoDir == "" {
		return nil, errors.New("repository directory is required")
	}
	if source == "" {
		return nil, errors.New("source description is required")
	}
	root := filepath.Join(repoDir, "osv", "malicious")
	if _, err := os.Stat(root); err != nil {
		return nil, err
	}
	out := &Output{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   b.now().UTC(),
		Source:        source,
		Packages:      make(map[string]map[string][]*Entry),
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := parseOSVFile(path)
		if err != nil {
			return err
		}
		aggregateRawInto(out, raw)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type rawRecord struct {
	ID         string      `json:"id"`
	Published  string      `json:"published"`
	Modified   string      `json:"modified"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Aliases    []string    `json:"aliases"`
	Affected   []rawTarget `json:"affected"`
	References []Reference `json:"references"`
}

type rawTarget struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions []string `json:"versions"`
	Ranges   []Range  `json:"ranges"`
}

func (r *rawRecord) trim() {
	r.Summary = strings.TrimSpace(r.Summary)
	r.Details = strings.TrimSpace(r.Details)
}

func normalizeEcosystem(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}

func cloneAndSort(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	sort.Strings(out)
	return out
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func cloneRanges(values []Range) []Range {
	if len(values) == 0 {
		return nil
	}
	out := make([]Range, len(values))
	for idx := range values {
		out[idx] = Range{
			Type:   values[idx].Type,
			Events: cloneRangeEvents(values[idx].Events),
		}
	}
	return out
}

func cloneRangeEvents(values []RangeEvent) []RangeEvent {
	if len(values) == 0 {
		return nil
	}
	out := make([]RangeEvent, len(values))
	copy(out, values)
	return out
}

func cloneReferences(values []Reference) []Reference {
	if len(values) == 0 {
		return nil
	}
	out := make([]Reference, len(values))
	copy(out, values)
	return out
}
