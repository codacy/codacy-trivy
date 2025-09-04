// Package tool implements the Codacy Trivy tool, including the Xeol EOL
// packages scanner for detecting end-of-life and soon-to-be-EOL packages.
package tool

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	ptypes "github.com/aquasecurity/trivy/pkg/types"
	codacy "github.com/codacy/codacy-engine-golang-seed/v6"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for xeol database
)

const (
	xeolCacheDir = "/dist/cache/xeol"
	xeolDBPath   = "/dist/cache/xeol/xeol.db"
)

func getXeolDBPath() string {
	if v := os.Getenv("XEOL_DB_PATH"); v != "" {
		return v
	}
	return xeolDBPath
}

// EOL product information from xeol database
type eolProduct struct {
	Name         string
	Permalink    string
	ReleaseCycle string
	EOL          *time.Time
	EOLBool      *bool
	Latest       string
}

// XeolScanner handles scanning for end-of-life packages using xeol's SQLite database
type XeolScanner struct {
	db *sql.DB
}

// NewXeolScanner creates a new Xeol EOL packages scanner
func NewXeolScanner() *XeolScanner {
	return &XeolScanner{}
}

// ScanForEOLPackages scans the given report for end-of-life packages
func (s *XeolScanner) ScanForEOLPackages(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	fmt.Println("DEBUG: XeolScanner.ScanForEOLPackages called")
	fmt.Printf("DEBUG: toolExecution.Patterns: %+v\n", toolExecution.Patterns)
	var results []codacy.Result

	// Check if any EOL patterns are enabled
	if !s.isEOLPatternEnabled(toolExecution.Patterns) {
		fmt.Println("DEBUG: No EOL patterns enabled, returning empty results")
		return results
	}
	fmt.Println("DEBUG: EOL patterns are enabled")

	if err := s.ensureDBConnection(); err != nil {
		fmt.Printf("Warning: Failed to connect to Xeol database: %v\n", err)
		return results
	}
	fmt.Println("DEBUG: Successfully connected to xeol database")
	defer s.closeDB()

	fmt.Printf("DEBUG: Found %d results to scan\n", len(report.Results))
	results = append(results, s.scanReportPackages(report, toolExecution)...)
	fmt.Printf("DEBUG: XeolScanner returning %d results\n", len(results))
	return results
}

// scanReportPackages processes Trivy results and detects EOL packages
func (s *XeolScanner) scanReportPackages(report ptypes.Report, toolExecution codacy.ToolExecution) []codacy.Result {
	var out []codacy.Result
	for _, r := range report.Results {
		out = append(out, s.scanSingleResult(r, toolExecution)...)
	}
	return out
}

// scanSingleResult handles a single Trivy result target
func (s *XeolScanner) scanSingleResult(result ptypes.Result, toolExecution codacy.ToolExecution) []codacy.Result {
	var out []codacy.Result

	for _, pkg := range result.Packages {
		if issues := s.checkPackage(pkg, result.Target, toolExecution); len(issues) > 0 {
			out = append(out, issues...)
		}
	}
	return out
}

// checkPackage checks a single package for EOL status
func (s *XeolScanner) checkPackage(pkg ftypes.Package, target string, toolExecution codacy.ToolExecution) []codacy.Result {
	pkgName := pkg.Name
	fmt.Printf("DEBUG: Checking package %s@%s\n", pkgName, pkg.Version)

	// Try to find EOL information for this package
	eolProducts, err := s.findEOLProducts(pkgName)
	if err != nil {
		fmt.Printf("DEBUG: Error finding EOL products for %s: %v\n", pkgName, err)
		return nil
	}
	if len(eolProducts) == 0 {
		fmt.Printf("DEBUG: No EOL products found for %s\n", pkgName)
		return nil
	}
	fmt.Printf("DEBUG: Found %d EOL products for %s\n", len(eolProducts), pkgName)

	var results []codacy.Result
	now := time.Now()

	for _, product := range eolProducts {
		fmt.Printf("DEBUG: Checking product %s (cycle: %s, eol: %v)\n", product.Name, product.ReleaseCycle, product.EOL)
		if s.packageMatches(pkg, product) {
			fmt.Printf("DEBUG: Package %s matches product %s\n", pkgName, product.Name)
			if issue := s.createEOLIssue(pkg, target, product, now, toolExecution); issue != nil {
				fmt.Printf("DEBUG: Created EOL issue for %s\n", pkgName)
				results = append(results, *issue)
			}
		}
	}

	return results
}

// findEOLProducts queries the xeol database for EOL information about a package
func (s *XeolScanner) findEOLProducts(packageName string) ([]eolProduct, error) {
	query := `
		SELECT p.name, p.permalink, c.release_cycle, c.eol, c.eol_bool, c.latest_release
		FROM products p 
		JOIN cycles c ON p.id = c.product_id 
		WHERE p.name = ? 
		AND (c.eol IS NOT NULL OR c.eol_bool IS NOT NULL)
		ORDER BY c.eol DESC
	`

	rows, err := s.db.Query(query, packageName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []eolProduct
	for rows.Next() {
		var product eolProduct
		var eolStr *string

		err := rows.Scan(
			&product.Name,
			&product.Permalink,
			&product.ReleaseCycle,
			&eolStr,
			&product.EOLBool,
			&product.Latest,
		)
		if err != nil {
			continue
		}

		// Parse EOL date if present
		if eolStr != nil && *eolStr != "" {
			if eolTime, err := time.Parse("2006-01-02", *eolStr); err == nil {
				product.EOL = &eolTime
			}
		}

		products = append(products, product)
	}

	return products, nil
}

// packageMatches determines if a package matches an EOL product
func (s *XeolScanner) packageMatches(pkg ftypes.Package, product eolProduct) bool {
	// Simple name matching for now - could be enhanced with version matching
	return strings.EqualFold(pkg.Name, product.Name)
}

// createEOLIssue creates an EOL issue based on the product's EOL status
func (s *XeolScanner) createEOLIssue(pkg ftypes.Package, target string, product eolProduct, now time.Time, toolExecution codacy.ToolExecution) *codacy.Issue {
	var ruleID string
	var message string
	var isEOL bool
	var eolDate string

	// Determine EOL status
	if product.EOL != nil {
		eolDate = product.EOL.Format("2006-01-02")
		isEOL = product.EOL.Before(now)
	} else if product.EOLBool != nil && *product.EOLBool {
		isEOL = true
		eolDate = "unknown"
	}

	// Check if package is already EOL or will be EOL soon (within 6 months)
	if isEOL {
		if !s.isPatternEnabled(toolExecution.Patterns, ruleIDEOLPackages) {
			return nil
		}
		ruleID = ruleIDEOLPackages
		message = fmt.Sprintf("End-of-life package detected: %s@%s (EOL: %s)", pkg.Name, pkg.Version, eolDate)
	} else if product.EOL != nil {
		// Check if EOL is within 6 months
		sixMonthsFromNow := now.AddDate(0, 6, 0)
		if product.EOL.Before(sixMonthsFromNow) {
			if !s.isPatternEnabled(toolExecution.Patterns, ruleIDEOLPackagesSoon) {
				return nil
			}
			ruleID = ruleIDEOLPackagesSoon
			message = fmt.Sprintf("Package approaching end-of-life: %s@%s (EOL: %s)", pkg.Name, pkg.Version, eolDate)
		} else {
			return nil // Not EOL and not approaching EOL
		}
	} else {
		return nil
	}

	lineNumber := s.findPackageLineNumber(toolExecution.SourceDir, target, pkg.Name)

	issue := codacy.Issue{
		File:      target,
		Message:   message,
		Line:      lineNumber,
		PatternID: ruleID,
		SourceID:  fmt.Sprintf("xeol-%s-%s", product.Name, product.ReleaseCycle),
	}

	if s.shouldAnalyzeFile(toolExecution.Files, target) {
		return &issue
	}
	return nil
}

// getPackageType extracts the package type from PURL or infers from target
func (s *XeolScanner) getPackageType(pkg ftypes.Package) string {
	if pkg.Identifier.PURL != nil {
		return strings.ToLower(pkg.Identifier.PURL.Type)
	}
	return ""
}

// ensureDBConnection establishes connection to xeol SQLite database
func (s *XeolScanner) ensureDBConnection() error {
	if s.db != nil {
		return nil
	}

	dbPath := getXeolDBPath()
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("xeol database not found at %s", dbPath)
	}

	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("failed to open xeol database: %w", err)
	}

	s.db = db
	return nil
}

// closeDB closes the database connection
func (s *XeolScanner) closeDB() {
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
}

// findPackageLineNumber finds the line number where a package is defined
func (s *XeolScanner) findPackageLineNumber(sourceDir, fileName, pkgName string) int {
	return fallbackSearchForLineNumber(sourceDir, fileName, pkgName)
}

// isEOLPatternEnabled checks if any EOL patterns are enabled
func (s *XeolScanner) isEOLPatternEnabled(patterns *[]codacy.Pattern) bool {
	if patterns == nil {
		return false
	}
	for _, pattern := range *patterns {
		if pattern.ID == ruleIDEOLPackages || pattern.ID == ruleIDEOLPackagesSoon {
			return true
		}
	}
	return false
}

// isPatternEnabled checks if a specific pattern is enabled
func (s *XeolScanner) isPatternEnabled(patterns *[]codacy.Pattern, patternID string) bool {
	if patterns == nil {
		return false
	}
	for _, pattern := range *patterns {
		if pattern.ID == patternID {
			return true
		}
	}
	return false
}

// shouldAnalyzeFile checks if the file should be analyzed
func (s *XeolScanner) shouldAnalyzeFile(knownFiles *[]string, fileName string) bool {
	if knownFiles == nil {
		return true
	}
	for _, file := range *knownFiles {
		if file == fileName {
			return true
		}
	}
	return false
}
