# Plan: Resolve Lizard Complexity Issues via Architectural Improvements

Target: bring NLOC and CCN within Lizard thresholds (function ≤50 lines, CCN ≤8) without changing behavior.

---

## 1. `internal/tool/tool.go` — getVulnerabilities (58 lines, CCN 14)

**Cause:** One large function that (1) builds a PURL→line map from packages, (2) filters result by severity, (3) loops over vulns with several conditionals (PURL skip, line fallback, fixed-version message, ruleID), and (4) builds issues.

**Approach:** Extract helpers so `getVulnerabilities` stays orchestration-only.

| Step | Action |
|------|--------|
| 1.1 | Add **`buildLineNumberByPurl(result ptypes.Result) map[string]int`** in `tool.go`. Single responsibility: from `result.Packages` produce PURL→line map. |
| 1.2 | Add **`vulnerabilityToIssue(target string, vuln ptypes.DetectedVulnerability, lineByPurl map[string]int, sourceDir string) (codacy.Issue, bool)`**. Encapsulates: PURL nil → false; line fallback; fixedVersion message; getRuleIDFromTrivySeverity; build Issue. Returns (issue, true) or (zero, false). |
| 1.3 | **Refactor getVulnerabilities:** Keep early exit and severity filter. For each result: `lineByPurl := buildLineNumberByPurl(result)`; FilterResult; loop vulns calling `vulnerabilityToIssue` and appending when true. Final line: same `mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(...))`. |

**Outcome:** getVulnerabilities shrinks to ~25 lines, CCN ~4; new helpers each small and low CCN.

---

## 2. `internal/tool/eol_scanner.go` — Scan (63 lines, CCN 15)

**Cause:** Scan does SBOM write, runner call, PURL→location build, and a loop with multiple branches (severity, location lookup, fallback, message formatting).

**Approach:** Extract SBOM I/O and “match → issue” logic.

| Step | Action |
|------|--------|
| 2.1 | Add **`writeSBOMToTemp(bom *cdx.BOM) (sbomPath string, cleanup func(), err error)`** in `eol_scanner.go`. Creates temp dir, writes `sbom.json`, returns path and `cleanup` (e.g. `os.RemoveAll(tmpDir)`). Caller: `defer cleanup()`. |
| 2.2 | Add **`matchToIssue(m eolMatch, report ptypes.Report, sourceDir string, files []string, purlToLocation map[string]pkgLocation) (codacy.Issue, bool)`**. Encapsulates: severityFromEolDate; PURL then findLocationByPackage; line fallback; message with optional CycleID; returns (issue, true) or (zero, false). Does not do filtering by files; caller filters. |
| 2.3 | **Refactor Scan:** Early exits unchanged. Call `sbomPath, cleanup, err := writeSBOMToTemp(bom)`; `defer cleanup()`; `matches, err := s.runner.Run(sbomPath)`; `purlToLocation := buildPURLToLocation(report)`; loop matches → `matchToIssue` → append; return `mapIssuesWithoutLineNumber(filterIssuesFromKnownFiles(issues, *toolExecution.Files))`. |

**Outcome:** Scan becomes ~25 lines, CCN ~5; helpers stay under limits.

---

## 3. `internal/docgen/rule.go` — trivyRules (104 lines)

**Cause:** One long function returning a large literal slice of similar structs (data, not logic).

**Approach:** Treat as data; avoid one giant function.

| Step | Action |
|------|--------|
| 3.1 | **Option A (preferred):** Move rule definitions to **data**. Add `internal/docgen/rules_data.go` (or `rules.yaml` + codegen). Define a slice `var trivyRulesList = []Rule{ ... }` (or load from YAML). `trivyRules()` becomes `return Rules(trivyRulesList)` or `return trivyRulesList`. Lizard counts lines of the slice initializer in a separate “block”; the exported `trivyRules()` stays tiny. |
| 3.2 | **Option B:** Split by category: **`secretRule()`**, **`vulnerabilityRules()`**, **`maliciousPackagesRule()`**, **`eolRules()`**, each returning 1–4 rules. **`trivyRules() Rules`** returns `append(append(append(secretRule(), vulnerabilityRules()...), maliciousPackagesRule()), eolRules()...)`. Each helper is under ~25 lines. |

**Outcome:** trivyRules (and any one helper in Option B) under 50 lines; no CCN concern.

---

## 4. `internal/openssfdb/builder.go` — Build walk callback (@97–148: 46 NLOC, CCN 11)

**Cause:** The `filepath.WalkDir` callback does file open, decode, trim, loop over Affected, normalize, build Entry, and map insert.

**Approach:** Move “one file” and “aggregate into output” into named functions.

| Step | Action |
|------|--------|
| 4.1 | Add **`parseOSVFile(path string) (*rawRecord, error)`**: open file, `json.Decode(&raw)`, `raw.trim()`, return raw. |
| 4.2 | Add **`aggregateRawInto(out *Output, raw *rawRecord)`**: loop over `raw.Affected`, normalize ecosystem, skip empty name/ecosystem, build Entry, ensure `out.Packages[ecosystem]` and `out.Packages[ecosystem][name]` exist, append entry. No file I/O. |
| 4.3 | **Refactor Build:** Walk callback: if not dir and not `.json` skip; `raw, err := parseOSVFile(path)`; if err return err; `aggregateRawInto(out, raw)`; return nil. |

**Outcome:** Callback shrinks to ~8 lines, CCN ~3; complexity lives in small, testable helpers.

---

## 5. `cmd/eoltest/main.go` — main (66 lines, CCN 13)

**Cause:** main does flag parsing, dir validation, index path resolution (with temp file), tool creation, file listing, execution, and result printing in one flow.

**Approach:** Extract “setup”, “run”, “print” so main is a short pipeline.

| Step | Action |
|------|--------|
| 5.1 | Add **`resolveIndexPath() (path string, cleanup func(), err error)`**: if default index path exists, return it and no-op cleanup; else create temp gzipped `{}`, return path and cleanup that removes it. |
| 5.2 | Add **`runEOLScan(ctx context.Context, dir, indexPath string) ([]codacy.Result, error)`**: `tool.New(indexPath)`, `listFiles(dir)`, build ToolExecution with EOL patterns, `trivy.Run(ctx, te)`, return results and error. |
| 5.3 | Add **`printEOLResults(results []codacy.Result)`**: loop results, switch on type (Issue vs FileError), print EOL issues and file errors; print “No EOL issues…” or “Total EOL issues: N”. |
| 5.4 | **Refactor main:** Parse and validate `-dir`; `indexPath, cleanup := resolveIndexPath()`; `defer cleanup()`; `results, err := runEOLScan(ctx, dir, indexPath)`; handle err; `printEOLResults(results)`. |

**Outcome:** main ~15 lines, CCN ~4; eoltest behavior unchanged.

---

## Order of implementation

1. **tool.go** (getVulnerabilities) — core tool; no new files.
2. **eol_scanner.go** (Scan) — same package, clear boundaries.
3. **cmd/eoltest/main.go** — small surface, fast win.
4. **openssfdb/builder.go** — localized to one file.
5. **docgen/rule.go** — Option B is minimal change; Option A is cleaner long-term.

## Verification

After each refactor:

- Run existing tests (`go test ./internal/tool/... ./cmd/eoltest/... ./internal/openssfdb/... ./internal/docgen/...`).
- Run `codacy-cli analyze -t lizard` and confirm NLOC/CCN for the touched functions are within thresholds.
