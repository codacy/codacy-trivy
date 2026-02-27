// Package tool - EOL runner using xeol Go library (no CLI subprocess).
package tool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/syft/syft/format"
	xeolPkg "github.com/xeol-io/xeol/xeol/pkg"
	xeolLib "github.com/xeol-io/xeol/xeol"
	"github.com/xeol-io/xeol/xeol/db"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/store"
	"github.com/xeol-io/xeol/xeol/xeolerr"
)

const lookahead365d = 365 * 24 * time.Hour

// XeolLibraryRunner runs EOL scan using the xeol Go library (no xeol binary required).
type XeolLibraryRunner struct {
	// DBCacheDir overrides XEOL_DB_CACHE_DIR when non-empty.
	DBCacheDir string
	// UpdateDB if true, allow DB update; set false for offline.
	UpdateDB bool
}

// Run decodes the SBOM at sbomPath, loads the xeol DB, runs FindEol, and returns eolMatch slice.
func (r *XeolLibraryRunner) Run(sbomPath string) ([]eolMatch, error) {
	packages, err := r.packagesFromSBOM(sbomPath)
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return []eolMatch{}, nil
	}

	store, closer, err := r.loadStore()
	if err != nil {
		return nil, err
	}
	if closer != nil {
		defer closer.Close()
	}

	eolMatchDate := time.Now().UTC().Add(lookahead365d)
	matches, err := xeolLib.FindEol(*store, nil, nil, packages, false, eolMatchDate)
	if err != nil && !errors.Is(err, xeolerr.ErrEolFound) {
		return nil, fmt.Errorf("find eol: %w", err)
	}
	return libMatchesToEolMatch(matches), nil
}

func (r *XeolLibraryRunner) packagesFromSBOM(sbomPath string) ([]xeolPkg.Package, error) {
	raw, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("open sbom: %w", err)
	}
	// Syft's CycloneDX decoder expects specVersion as string (e.g. "1.6"); Trivy may emit a number.
	raw = normalizeCycloneDXSpecVersion(raw)
	decoded, _, _, err := format.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode sbom: %w", err)
	}
	if decoded == nil || decoded.Artifacts.Packages == nil {
		return nil, nil
	}
	config := xeolPkg.SynthesisConfig{GenerateMissingCPEs: false}
	return xeolPkg.FromCollection(decoded.Artifacts.Packages, config), nil
}

// normalizeCycloneDXSpecVersion ensures specVersion is a JSON string so syft's decoder can identify the format.
func normalizeCycloneDXSpecVersion(b []byte) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return b
	}
	if v, ok := m["specVersion"]; ok {
		switch t := v.(type) {
		case string:
			return b
		case float64:
			// Syft supports 1.2–1.6; Trivy/cyclonedx-go often use integer (e.g. 7 for 1.6).
			n := int(t)
			if n >= 0 && n <= 6 {
				m["specVersion"] = fmt.Sprintf("1.%d", n)
			} else {
				m["specVersion"] = "1.6"
			}
			out, _ := json.Marshal(m)
			return out
		}
	}
	return b
}

func (r *XeolLibraryRunner) loadStore() (*store.Store, *db.Closer, error) {
	cfg := r.dbConfig()
	store, _, closer, err := xeolLib.LoadEolDB(cfg, r.UpdateDB)
	if err != nil {
		return nil, nil, fmt.Errorf("load xeol db: %w", err)
	}
	return store, closer, nil
}

func (r *XeolLibraryRunner) dbConfig() db.Config {
	rootDir := r.DBCacheDir
	if rootDir == "" {
		rootDir = os.Getenv("XEOL_DB_CACHE_DIR")
	}
	if rootDir == "" {
		// Default: XDG cache (e.g. ~/Library/Caches/xeol/db on macOS)
		rootDir = filepath.Join(os.Getenv("HOME"), ".cache", "xeol", "db")
		if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
			rootDir = filepath.Join(d, "xeol", "db")
		}
	}
	return db.Config{
		DBRootDir: rootDir,
		// ListingURL left empty to use xeol default
	}
}

func libMatchesToEolMatch(m match.Matches) []eolMatch {
	out := make([]eolMatch, 0, m.Count())
	for m := range m.Enumerate() {
		purl := m.Package.PURL
		if purl == "" {
			purl = "pkg:generic/" + m.Package.Name + "@" + m.Package.Version
		}
		out = append(out, eolMatch{
			PURL:    purl,
			Name:    m.Package.Name,
			Version: m.Package.Version,
			EolDate: m.Cycle.Eol,
			CycleID: m.Cycle.ReleaseCycle,
		})
	}
	return out
}
