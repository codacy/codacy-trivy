# Step 1: XEOL API and output structure verification

This document completes **Step 1** of the XEOL EOL Detection Integration Plan: verify xeol API and output structure for implementing the four severity bands (critical / high / medium / minor).

## 1. Input: in-memory BOM vs path

- **Library**: The xeol Go library (`github.com/xeol-io/xeol/xeol`) can run `FindEol` with a package catalog. However, adding `github.com/xeol-io/xeol` as a direct dependency pulls in `anchore/syft` and `anchore/fangs`, which **conflicted (tablewriter/viper)**; build fixed via go.mod replace with this project’s toolchain (Go 1.25 + `GOEXPERIMENT=jsonv2`). We **use the Go library** (see `internal/tool/eol_xeol_lib.go`); build fixed via go.mod replace.
- **CLI**: The xeol CLI accepts **path-based input only** for SBOMs:
  - `xeol sbom:path/to/sbom.json` (or pipe: `cat sbom.json | xeol`).
  - Supported formats: **Syft, SPDX, CycloneDX** ([README](https://github.com/xeol-io/xeol)).
- **Conclusion**: Write the Trivy-generated CycloneDX BOM to a temporary file; the **xeol library** decodes it (syft format), loads the EOL DB, and runs FindEol. No xeol binary required.

## 2. Output: EOL date and four severity bands

- **EOL date in matches**: The plan’s Clarifications state that **Match.Cycle exposes `Eol`** (string date, e.g. `"2025-06-01"`). The DB overview ([docs/xeol-db-overview.md](xeol-db-overview.md)) confirms that cycles have an `eol` date and that we can **compute days until EOL** and map to Codacy severity.
- **Lookahead**: The CLI supports `--lookahead` (e.g. `1w`, `30d`, `1y`). Default is 30 days. For our bands we need matches up to “longer than 6 months” (minor). Use a long lookahead (e.g. `--lookahead 1y`) so xeol returns all relevant matches; we then **classify each match** by days until EOL into:
  - **Now obsolete** (EOL date in the past): **critical** (`eol_critical`).
  - **Within 1 month of expiry**: **high** (`eol_high`).
  - **Within 6 months**: **medium** (`eol_medium`).
  - **Longer than 6 months**: **minor** (`eol_minor`).
- **CLI JSON**: The CLI can output JSON (e.g. `-o json`). The exact top-level and per-match structure (e.g. package identifier, cycle, EOL date field name) should be **confirmed at implementation time** from xeol’s presenter code or a sample run (`xeol sbom:<path> -o json`). The integration will parse that JSON and read the EOL date string for each match to compute days and assign the rule ID.

## 3. Summary

| Question | Answer |
|----------|--------|
| Can we scan from an in-memory CycloneDX BOM? | Library builds (see go.mod replace). CLI accepts path only. Use temp file + `xeol sbom:<path>`, or library API if preferred. |
| Does each match include EOL/cycle end date? | Yes. Match.Cycle has `Eol` (string date). We can compute days until EOL. |
| Can we implement all four bands (obsolete, &lt;1 month, &lt;6 months, &gt;6 months)? | Yes. Parse EOL date, compute days, map to `eol_critical` / `eol_high` / `eol_medium` / `eol_minor`. |
| Integration approach | Use **xeol Go library**: write CycloneDX to temp file, decode with syft format, LoadEolDB + FindEol, map matches to Codacy issues. CLI runner available as fallback. |

Step 1 is **complete**. Proceed to Step 2 (EOL rules and docgen).
