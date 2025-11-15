package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

// RiskLevel represents the severity of a finding
type RiskLevel string

const (
	HighRisk   RiskLevel = "HIGH RISK"
	MediumRisk RiskLevel = "MEDIUM RISK"
	LowRisk    RiskLevel = "LOW RISK"
	Suspicious RiskLevel = "SUSPICIOUS"
)

// FilterLevel represents the filtering mode
type FilterLevel string

const (
	FilterAll    FilterLevel = "ALL"
	FilterHigh   FilterLevel = "HIGH"
	FilterMedium FilterLevel = "MEDIUM"
)

// Pattern represents a detection pattern
type Pattern struct {
	Name        string
	Risk        RiskLevel
	Category    string // Category: supply-chain, credential-theft, persistence, obfuscation, network, execution, cloud
	Description string
	Regex       *regexp.Regexp
	FileTypes   []string                  // Empty means all files
	Validator   func(content string) bool // Additional validation beyond regex
}

// Scanner holds the scanner configuration
type Scanner struct {
	Patterns       []Pattern
	FilterLevel    FilterLevel
	FilterCategory string // Filter by category (empty = all categories)
	IssuesFound    int
	ScanPath       string
	SkipBinary     bool
	MaxFileSize    int64
	PatternStats   map[string]int // Pattern name -> match count for statistics
	IgnorePatterns []string       // Patterns from .sketchyignore file
}

// Color functions
var (
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	purple = color.New(color.FgMagenta).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

func main() {
	var (
		scanPath   = flag.String("path", ".", "Path to scan")
		highOnly   = flag.Bool("high-only", false, "Only show HIGH RISK findings")
		mediumUp   = flag.Bool("medium-up", false, "Show MEDIUM and HIGH RISK findings")
		category   = flag.String("category", "", "Filter by category (supply-chain, credential-theft, persistence, obfuscation, network, execution, cloud)")
		stats      = flag.Bool("stats", false, "Show pattern statistics after scan")
		help       = flag.Bool("help", false, "Show help")
		skipBinary = flag.Bool("skip-binary", true, "Skip binary files")
	)

	flag.Parse()

	// Handle install-hook command
	if flag.NArg() > 0 && flag.Arg(0) == "install-hook" {
		if err := installHook(); err != nil {
			fmt.Fprintf(os.Stderr, "Error installing hook: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *help {
		printHelp()
		os.Exit(0)
	}

	// If no arguments provided, check for hook installation and prompt
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		checkAndPromptHookInstallation()
		printHelp()
		os.Exit(0)
	}

	// Handle positional argument
	if flag.NArg() > 0 {
		*scanPath = flag.Arg(0)
	}

	filterLevel := FilterAll
	if *highOnly {
		filterLevel = FilterHigh
	} else if *mediumUp {
		filterLevel = FilterMedium
	}

	scanner := NewScanner(*scanPath, filterLevel, *category, *skipBinary)

	fmt.Printf("%s\n", yellow("🔍 Scanning: "+*scanPath))
	if *category != "" {
		fmt.Printf("%s\n", yellow("📁 Category filter: "+*category))
	}
	fmt.Println("================================")

	if err := scanner.Scan(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	scanner.PrintSummary()

	if *stats {
		scanner.PrintStats()
	}

	os.Exit(scanner.IssuesFound)
}

func printHelp() {
	fmt.Println("sketchy - Security scanner for repositories")
	fmt.Println("\nUsage: sketchy [options] [path]")
	fmt.Println("       sketchy install-hook")
	fmt.Println("\nOptions:")
	fmt.Println("  -path string      Path to scan (default \".\")")
	fmt.Println("  -high-only        Only show HIGH RISK findings")
	fmt.Println("  -medium-up        Show MEDIUM and HIGH RISK findings")
	fmt.Println("  -category string  Filter by category (supply-chain, credential-theft, persistence, obfuscation, network, execution, cloud)")
	fmt.Println("  -stats            Show pattern statistics after scan")
	fmt.Println("  -skip-binary      Skip binary files (default true)")
	fmt.Println("  -help             Show this help message")
	fmt.Println("\nCommands:")
	fmt.Println("  install-hook      Install git post-checkout hook to scan repos after clone")
}

// NewScanner creates a new scanner instance
func NewScanner(path string, filter FilterLevel, category string, skipBinary bool) *Scanner {
	s := &Scanner{
		ScanPath:       path,
		FilterLevel:    filter,
		FilterCategory: category,
		SkipBinary:     skipBinary,
		MaxFileSize:    1024 * 1024, // 1MB
		PatternStats:   make(map[string]int),
		IgnorePatterns: []string{},
	}
	s.initPatterns()

	// Load .sketchyignore file if it exists
	ignoreFile := findIgnoreFile(path)
	if ignoreFile != "" {
		patterns, err := loadIgnoreFile(ignoreFile)
		if err == nil {
			s.IgnorePatterns = patterns
		}
	}

	return s
}

// Scan performs the security scan
func (s *Scanner) Scan() error {
	return filepath.Walk(s.ScanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip directories and special files
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		// Skip files that are too large
		if info.Size() > s.MaxFileSize {
			return nil
		}

		// Skip common non-text files
		if s.shouldSkipFile(path) {
			return nil
		}

		// Check the file
		s.checkFile(path)
		return nil
	})
}

// shouldSkipFile determines if a file should be skipped
func (s *Scanner) shouldSkipFile(path string) bool {
	// Check .sketchyignore patterns first
	if len(s.IgnorePatterns) > 0 && shouldIgnore(path, s.IgnorePatterns, s.ScanPath) {
		return true
	}

	// Skip hidden directories (like .git, .vscode, etc.)
	if isHiddenDirectory(path) {
		return true
	}

	// Skip common binary/media file extensions
	if hasBinaryExtension(path) {
		return true
	}

	// Check if file is binary (by content)
	if s.SkipBinary {
		if isBinary, _ := isBinaryFile(path); isBinary {
			return true
		}
	}

	return false
}

// isHiddenDirectory checks if the file is in a hidden directory
func isHiddenDirectory(path string) bool {
	dir := filepath.Dir(path)
	// Check each component of the path for hidden directories (starting with .)
	parts := strings.Split(filepath.ToSlash(dir), "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") && len(part) > 1 {
			return true
		}
	}
	return false
}

// hasBinaryExtension checks if file has a binary/media extension
func hasBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		// Images
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".ico": true, ".svg": true,
		// Videos
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wmv": true,
		// Archives
		".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".7z": true, ".rar": true,
		// Binaries
		".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true,
		// Documents
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		// Compiled code
		".pyc": true, ".pyo": true, ".class": true, ".jar": true,
		// Fonts
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	}
	return binaryExts[ext]
}

// isBinaryFile checks if a file appears to be binary
func isBinaryFile(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Read first 512 bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	buf = buf[:n]

	// Check for null bytes (common in binary files)
	if bytes.Contains(buf, []byte{0}) {
		return true, nil
	}

	// Check if mostly printable ASCII
	nonPrintable := 0
	for _, b := range buf {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(len(buf)) > 0.3, nil
}

// checkFile scans a single file for patterns
func (s *Scanner) checkFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	contentStr := string(content)
	relPath, _ := filepath.Rel(s.ScanPath, path)

	for _, pattern := range s.Patterns {
		// Skip if category filter doesn't match
		if s.FilterCategory != "" && pattern.Category != s.FilterCategory {
			continue
		}

		// Skip if file type doesn't match
		if !s.matchesFileType(pattern, path) {
			continue
		}

		// Check if pattern matches and get matches
		matches := s.checkPattern(pattern, contentStr)
		if len(matches) > 0 {
			if s.shouldDisplay(pattern.Risk) {
				if pattern.Regex == nil {
					// Validator-only patterns
					s.printValidatorMatch(pattern, relPath)
				} else {
					// Patterns with regex matches
					s.printMatch(pattern, relPath, contentStr, matches)
				}
			}
			s.IssuesFound++
			s.PatternStats[pattern.Name]++
		}
	}
}

// matchesFileType checks if a pattern applies to the given file path
func (s *Scanner) matchesFileType(pattern Pattern, path string) bool {
	// If no file type restriction, pattern applies to all files
	if len(pattern.FileTypes) == 0 {
		return true
	}

	// Check if file path ends with any of the specified file types
	for _, ft := range pattern.FileTypes {
		if strings.HasSuffix(path, ft) {
			return true
		}
	}
	return false
}

// checkPattern checks if a pattern matches and returns the matches
// Returns empty slice if pattern doesn't match, or slice of match indices if it does
func (s *Scanner) checkPattern(pattern Pattern, content string) [][]int {
	// Validator-only patterns (e.g., Unicode character checks)
	if pattern.Validator != nil && pattern.Regex == nil {
		if pattern.Validator(content) {
			return [][]int{{0, 0}} // Return dummy match to indicate pattern matched
		}
		return nil
	}

	// Regex-only patterns
	if pattern.Regex != nil && pattern.Validator == nil {
		matches := pattern.Regex.FindAllStringIndex(content, 3)
		if pattern.Name == "suspicious-network" {
			matches = filterLocalhostMatches(content, matches)
		}
		return matches
	}

	// Patterns with both regex and validator
	// Validator acts as a pre-filter (e.g., filters out localhost)
	// If validator passes, then find regex matches
	if pattern.Regex != nil && pattern.Validator != nil {
		if !pattern.Validator(content) {
			return nil // Validator failed, pattern doesn't match
		}
		matches := pattern.Regex.FindAllStringIndex(content, 3)
		if pattern.Name == "suspicious-network" {
			matches = filterLocalhostMatches(content, matches)
		}
		return matches
	}

	return nil
}

// shouldDisplay checks if a risk level should be displayed based on filter
func (s *Scanner) shouldDisplay(risk RiskLevel) bool {
	switch s.FilterLevel {
	case FilterHigh:
		return risk == HighRisk
	case FilterMedium:
		return risk == HighRisk || risk == MediumRisk
	default:
		return true
	}
}

// printMatch prints a pattern match
func (s *Scanner) printMatch(pattern Pattern, file string, content string, matches [][]int) {
	riskColor := s.getRiskColor(pattern.Risk)
	fmt.Printf("%s %s - %s\n", riskColor(string(pattern.Risk)), riskColor(pattern.Description), pattern.Name)

	for i, match := range matches {
		if i >= 3 {
			break // Only show first 3 matches
		}

		lineNum, preview := getLineInfo(content, match[0])
		fmt.Printf("%s  File: %s:%d\n", blue(""), file, lineNum)

		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		fmt.Printf("  Preview: %s\n\n", preview)
	}
}

// printValidatorMatch prints a match found by validator only
func (s *Scanner) printValidatorMatch(pattern Pattern, file string) {
	riskColor := s.getRiskColor(pattern.Risk)
	fmt.Printf("%s %s - %s\n", riskColor(string(pattern.Risk)), riskColor(pattern.Description), pattern.Name)
	fmt.Printf("%s  File: %s\n", blue(""), file)
	fmt.Printf("  Preview: [Requires manual review]\n\n")
}

// getRiskColor returns the appropriate color function for a risk level
func (s *Scanner) getRiskColor(risk RiskLevel) func(a ...interface{}) string {
	switch risk {
	case HighRisk:
		return red
	case MediumRisk:
		return yellow
	case LowRisk:
		return yellow
	case Suspicious:
		return purple
	default:
		return fmt.Sprint
	}
}

// filterLocalhostMatches filters out matches that contain localhost or 127.0.0.1
// This is used for patterns like suspicious-network that should exclude localhost
func filterLocalhostMatches(content string, matches [][]int) [][]int {
	filtered := [][]int{}
	for _, match := range matches {
		if len(match) >= 2 {
			matchedText := content[match[0]:match[1]]
			// Check if this match contains localhost or 127.x.x.x
			if strings.Contains(matchedText, "://127.") || strings.Contains(matchedText, "://localhost") {
				continue // Skip localhost matches
			}
			// Also check for IP addresses starting with 127.
			if ipMatch := regexp.MustCompile(`https?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`).FindStringSubmatch(matchedText); len(ipMatch) > 1 {
				if strings.HasPrefix(ipMatch[1], "127.") {
					continue // Skip 127.x.x.x addresses
				}
			}
			filtered = append(filtered, match)
		}
	}
	return filtered
}

// getLineInfo gets line number and content for a position
func getLineInfo(content string, pos int) (int, string) {
	lineNum := 1
	lineStart := 0

	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			lineNum++
			lineStart = i + 1
		}
	}

	lineEnd := pos
	for lineEnd < len(content) && content[lineEnd] != '\n' {
		lineEnd++
	}

	line := strings.TrimSpace(content[lineStart:lineEnd])
	return lineNum, line
}

// PrintSummary prints the scan summary
func (s *Scanner) PrintSummary() {
	fmt.Println("================================")
	if s.IssuesFound == 0 {
		fmt.Printf("%s\n", green("✅ Scan complete. No suspicious patterns detected."))
	} else {
		fmt.Printf("%s\n", red(fmt.Sprintf("⚠️  Scan complete. Found %d potential issue(s).", s.IssuesFound)))
	}
}

// PrintStats prints pattern statistics
func (s *Scanner) PrintStats() {
	fmt.Println("\n📊 Pattern Statistics:")
	fmt.Println("================================")

	if len(s.PatternStats) == 0 {
		fmt.Println("No patterns matched.")
		return
	}

	// Sort patterns by match count (descending)
	type patternStat struct {
		name  string
		count int
	}
	stats := make([]patternStat, 0, len(s.PatternStats))
	for name, count := range s.PatternStats {
		stats = append(stats, patternStat{name: name, count: count})
	}

	// Simple bubble sort (fine for small number of patterns)
	for i := 0; i < len(stats)-1; i++ {
		for j := 0; j < len(stats)-i-1; j++ {
			if stats[j].count < stats[j+1].count {
				stats[j], stats[j+1] = stats[j+1], stats[j]
			}
		}
	}

	// Print top patterns
	fmt.Printf("%s\n", bold("Most matched patterns:"))
	for _, stat := range stats {
		fmt.Printf("  %s: %d match(es)\n", stat.name, stat.count)
	}

	// Show patterns that never matched
	matchedPatterns := make(map[string]bool)
	for name := range s.PatternStats {
		matchedPatterns[name] = true
	}

	unmatched := []string{}
	for _, pattern := range s.Patterns {
		if !matchedPatterns[pattern.Name] {
			unmatched = append(unmatched, pattern.Name)
		}
	}

	if len(unmatched) > 0 {
		fmt.Printf("\n%s\n", bold("Patterns with no matches:"))
		for _, name := range unmatched {
			fmt.Printf("  %s\n", name)
		}
	}
}

// findIgnoreFile searches for .sketchyignore file starting from path and going up to repo root
func findIgnoreFile(startPath string) string {
	// Get absolute path
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return ""
	}

	// If it's a file, get its directory
	if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
		absPath = filepath.Dir(absPath)
	}

	// Search up the directory tree
	current := absPath
	for {
		ignorePath := filepath.Join(current, ".sketchyignore")
		if _, err := os.Stat(ignorePath); err == nil {
			return ignorePath
		}

		// Stop at root directory
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return ""
}

// loadIgnoreFile reads and parses a .sketchyignore file
func loadIgnoreFile(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	patterns := []string{}
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Add pattern (preserve negation prefix !)
		patterns = append(patterns, line)
	}

	return patterns, nil
}

// shouldIgnore checks if a path matches any ignore pattern from .sketchyignore
func shouldIgnore(path string, patterns []string, scanPath string) bool {
	// Get relative path from scan path
	relPath, err := filepath.Rel(scanPath, path)
	if err != nil {
		relPath = path
	}
	relPath = filepath.ToSlash(relPath) // Normalize to forward slashes

	ignored := false
	negated := false

	for _, pattern := range patterns {
		isNegation := strings.HasPrefix(pattern, "!")
		actualPattern := strings.TrimPrefix(pattern, "!")
		actualPattern = filepath.ToSlash(actualPattern)

		if matchesPattern(actualPattern, relPath) {
			if isNegation {
				negated = true
			} else {
				ignored = true
			}
		}
	}

	// Negation overrides ignore (e.g., !test/important.py overrides test/)
	if negated {
		return false // Don't ignore if negated
	}
	return ignored
}

// matchesPattern checks if a pattern matches a path
func matchesPattern(pattern, path string) bool {
	// Directory pattern (ending with /)
	if strings.HasSuffix(pattern, "/") {
		dir := strings.TrimSuffix(pattern, "/")
		return strings.HasPrefix(path, dir+"/") || path == dir
	}

	// Try exact match first
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}

	// Try matching against path components
	pathParts := strings.Split(path, "/")
	for i := range pathParts {
		// Match from this component onwards
		testPath := strings.Join(pathParts[i:], "/")
		if matched, _ := filepath.Match(pattern, testPath); matched {
			return true
		}
		// Match this component
		if matched, _ := filepath.Match(pattern, pathParts[i]); matched {
			return true
		}
	}

	return false
}

// installHook installs a git post-checkout hook that runs sketchy after clone
func installHook() error {
	fmt.Println("Install hook in:")
	fmt.Println("  1. Current repository only")
	fmt.Println("  2. Global git template (applies to all new clones)")
	fmt.Print("Choice (1 or 2): ")

	var choice string
	fmt.Scanln(&choice)

	if choice == "2" {
		return installGlobalHook()
	}

	// Install in current repository
	gitDir, err := findGitDir(".")
	if err != nil {
		return fmt.Errorf("not a git repository: %v", err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "post-checkout")
	return writeHook(hookPath, "✅ Git post-checkout hook installed successfully!")
}

// findGitDir searches for .git directory starting from path
func findGitDir(startPath string) (string, error) {
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return "", err
	}

	current := absPath
	for {
		gitPath := filepath.Join(current, ".git")
		if info, err := os.Stat(gitPath); err == nil {
			if info.IsDir() {
				return gitPath, nil
			}
		}

		// Stop at root directory
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", fmt.Errorf(".git directory not found")
}

// getSketchyPath finds the sketchy binary path
func getSketchyPath() (string, error) {
	// Try to get the executable path
	execPath, err := os.Executable()
	if err != nil {
		// Fallback: try to find in PATH
		return "sketchy", nil // Let the hook try to find it in PATH
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(execPath)
	if err != nil {
		return execPath, nil
	}

	return absPath, nil
}

// installGlobalHook installs the hook in Git's global template directory
func installGlobalHook() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %v", err)
	}

	// Find or create template directory
	templateDir := findOrCreateTemplateDir(homeDir)
	if templateDir == "" {
		return fmt.Errorf("could not create template directory")
	}

	hookPath := filepath.Join(templateDir, "hooks", "post-checkout")
	if err := writeHook(hookPath, "✅ Global git hook template installed!"); err != nil {
		return err
	}

	fmt.Printf("   Template location: %s\n", templateDir)
	fmt.Printf("   Hook location: %s\n", hookPath)
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Configure git to use this template:")
	fmt.Printf("   git config --global init.templateDir %s\n", templateDir)
	fmt.Println()
	fmt.Println("   After this, all NEW git clones will have the hook installed.")
	fmt.Println("   (Existing repos won't be affected)")

	return nil
}

// findOrCreateTemplateDir finds an existing git template directory or creates one
func findOrCreateTemplateDir(homeDir string) string {
	// Check common template locations
	templateDirs := []string{
		filepath.Join(homeDir, ".git-template"),
		filepath.Join(homeDir, ".config", "git", "template"),
		filepath.Join(homeDir, ".git-templates"),
	}

	// Use existing directory if found
	for _, dir := range templateDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}

	// Create new template directory (use first option)
	templateDir := templateDirs[0]
	if err := os.MkdirAll(templateDir, 0755); err != nil {
		return ""
	}
	return templateDir
}

// writeHook writes the hook script to the specified path
func writeHook(hookPath string, successMsg string) error {
	// Check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		fmt.Printf("⚠️  Hook already exists at %s\n", hookPath)
		fmt.Print("Overwrite? (y/n): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Installation cancelled.")
			return nil
		}
	}

	// Get sketchy binary path
	sketchyPath, err := getSketchyPath()
	if err != nil {
		return fmt.Errorf("could not find sketchy binary: %v", err)
	}

	// Create hooks directory if needed
	hooksDir := filepath.Dir(hookPath)
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("could not create hooks directory: %v", err)
	}

	// Generate and write hook script
	hookScript := generatePostCheckoutHook(sketchyPath)
	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return fmt.Errorf("could not write hook file: %v", err)
	}

	fmt.Printf("%s\n", green(successMsg))
	if strings.Contains(successMsg, "Global") {
		// Global hook message already printed above
	} else {
		fmt.Printf("   Hook location: %s\n", hookPath)
		fmt.Printf("   The hook will run sketchy automatically after git clone/checkout\n")
	}

	return nil
}

// generatePostCheckoutHook generates the post-checkout hook script
func generatePostCheckoutHook(sketchyPath string) string {
	// Use a shell script that works on both Unix and Windows (Git Bash)
	script := `#!/bin/sh
# Git post-checkout hook - Runs sketchy security scanner after clone/checkout
# Installed by: sketchy install-hook

# Run on initial clone (when previous HEAD is null) or branch checkout
# $1 = previous HEAD, $2 = new HEAD, $3 = branch checkout flag (1) or file checkout (0)
# For git clone: $1 will be 0000000000000000000000000000000000000000
# For branch switch: $3 will be 1
if [ "$1" = "0000000000000000000000000000000000000000" ] || [ "$3" = "1" ]; then
    echo ""
    echo "🔍 Running sketchy security scan on repository..."
    echo "================================================"
    
    # Try to find sketchy in this order:
    # 1. Local executable in repo (sketchy.exe or sketchy)
    # 2. Executable in PATH
    # 3. Absolute path provided during installation
    
    SKETCHY_CMD=""
    
    # Check for local executable in repo root
    if [ -f "./sketchy.exe" ]; then
        SKETCHY_CMD="./sketchy.exe"
    elif [ -f "./sketchy" ]; then
        SKETCHY_CMD="./sketchy"
    # Check in PATH
    elif command -v sketchy >/dev/null 2>&1; then
        SKETCHY_CMD="sketchy"
    # Try absolute path from installation (properly quoted for spaces)
    elif [ -f "` + escapeShellPath(sketchyPath) + `" ]; then
        SKETCHY_CMD="` + escapeShellPath(sketchyPath) + `"
    fi
    
    if [ -n "$SKETCHY_CMD" ]; then
        "$SKETCHY_CMD" -path .
        SCAN_EXIT=$?
    else
        echo "⚠️  sketchy not found. Skipping scan."
        echo "   Make sure sketchy.exe (or sketchy) is in the repository root or in your PATH."
        exit 0
    fi
    
    echo ""
    if [ $SCAN_EXIT -ne 0 ]; then
        echo "⚠️  Security scan found potential issues. Review the output above."
        echo "   (This is a warning only - checkout completed successfully)"
    else
        echo "✅ Security scan completed - no issues detected."
    fi
    echo ""
fi

exit 0
`
	return script
}

// escapeShellPath properly escapes a path for use in shell scripts
func escapeShellPath(path string) string {
	// Replace backslashes with forward slashes for cross-platform compatibility
	path = strings.ReplaceAll(path, "\\", "/")
	// Return path without quotes (template will add quotes)
	return path
}

// checkAndPromptHookInstallation checks if git hook is installed and prompts if not
func checkAndPromptHookInstallation() {
	if isHookInstalled() {
		return // Hook already installed, no need to prompt
	}

	fmt.Println()
	fmt.Printf("%s\n", yellow("🔧 First time using sketchy?"))
	fmt.Println("   Install a git hook to automatically scan repositories after cloning!")
	fmt.Println()
	fmt.Print("   Would you like to install the git hook? (y/n): ")

	var response string
	fmt.Scanln(&response)
	if response == "y" || response == "Y" {
		fmt.Println()
		if err := installHook(); err != nil {
			fmt.Fprintf(os.Stderr, "Error installing hook: %v\n", err)
		} else {
			fmt.Println()
		}
	} else {
		fmt.Println("   You can install it later with: sketchy install-hook")
		fmt.Println()
	}
}

// isHookInstalled checks if a sketchy git hook is already installed
func isHookInstalled() bool {
	// Check local repository hook
	if gitDir, err := findGitDir("."); err == nil {
		hookPath := filepath.Join(gitDir, "hooks", "post-checkout")
		if isSketchyHook(hookPath) {
			return true
		}
	}

	// Check global template hooks
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	templateHooks := []string{
		filepath.Join(homeDir, ".git-template", "hooks", "post-checkout"),
		filepath.Join(homeDir, ".config", "git", "template", "hooks", "post-checkout"),
		filepath.Join(homeDir, ".git-templates", "hooks", "post-checkout"),
	}

	for _, hookPath := range templateHooks {
		if isSketchyHook(hookPath) {
			return true
		}
	}

	return false
}

// isSketchyHook checks if a hook file exists and contains sketchy
func isSketchyHook(hookPath string) bool {
	info, err := os.Stat(hookPath)
	if err != nil || info.IsDir() {
		return false
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		return false
	}

	return strings.Contains(string(content), "sketchy")
}

// checkForBidiChars checks for bidirectional Unicode characters
func checkForBidiChars(content string) bool {
	// Check for bidirectional override characters
	bidiChars := []rune{
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // LTR/RTL embedding
		0x2066, 0x2067, 0x2068, 0x2069, // Isolate characters
	}

	for _, char := range bidiChars {
		if strings.ContainsRune(content, char) {
			return true
		}
	}

	// Also check raw bytes for these UTF-8 sequences
	contentBytes := []byte(content)
	bidiPatterns := [][]byte{
		{0xe2, 0x80, 0xaa}, {0xe2, 0x80, 0xab}, {0xe2, 0x80, 0xac},
		{0xe2, 0x80, 0xad}, {0xe2, 0x80, 0xae},
		{0xe2, 0x81, 0xa6}, {0xe2, 0x81, 0xa7}, {0xe2, 0x81, 0xa8}, {0xe2, 0x81, 0xa9},
	}

	for _, pattern := range bidiPatterns {
		if bytes.Contains(contentBytes, pattern) {
			return true
		}
	}

	return false
}

// checkForCyrillic checks for Cyrillic characters (homograph attacks)
func checkForCyrillic(content string) bool {
	for _, r := range content {
		if r >= 0x0400 && r <= 0x04FF {
			return true
		}
	}
	return false
}

// checkForNonASCII checks for non-ASCII characters
func checkForNonASCII(content string) bool {
	for _, r := range content {
		if r > 127 {
			return true
		}
	}
	return false
}
