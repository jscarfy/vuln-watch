package main

import (
	"flag"
	"fmt"
	"github.com/jscarfy/vuln-watch/internal/config"
	"github.com/jscarfy/vuln-watch/internal/report"
	"os"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup
var maxRetries = 3

func main() {
	var cfgPath string
	var minSeverity string
	var verbosity int
	var totalPackages int
	var excludeVersions string

	flag.StringVar(&cfgPath, "config", "configs/example.yaml", "Path to config YAML")
	flag.StringVar(&minSeverity, "severity", "LOW", "Minimum severity for vulnerabilities (LOW, MEDIUM, HIGH, CRITICAL)")
	flag.IntVar(&verbosity, "verbosity", 1, "Verbosity level (0=quiet, 1=normal, 2=verbose)")
	flag.StringVar(&excludeVersions, "exclude-versions", "", "Comma-separated list of versions to exclude from scans")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(cfgPath)
	if err != nil {
		logError("Unable to load config", err)
		os.Exit(1)
	}

	// Calculate total number of packages to query
	for _, src := range cfg.Sources {
		totalPackages += len(src.Packages)
	}

	// Query each source in the config concurrently
	var totalVulns int
	for _, src := range cfg.Sources {
		fmt.Println("Querying source:", src.Name)

		// Query vulnerabilities for each package
		for _, pkg := range src.Packages {
			// Skip package if its version is in the exclusion list
			if isVersionExcluded(pkg.Version, excludeVersions) {
				fmt.Printf("Skipping package %s version %s (excluded)\n", pkg.Name, pkg.Version)
				continue
			}

			wg.Add(1)
			go func(pkg config.Package) {
				defer wg.Done()
				if err := queryOSV(pkg, minSeverity, verbosity); err != nil {
					logError("Error querying OSV", err)
				}
			}(pkg)
		}
	}

	// Show progress updates
	for i := 0; i < totalPackages; i++ {
		if verbosity > 0 {
			fmt.Printf("\rProgress: %d/%d packages queried", i+1, totalPackages)
		}
		time.Sleep(100 * time.Millisecond) // Simulate some delay
	}
	wg.Wait()

	// Print summary of vulnerabilities
	fmt.Printf("\nVulnerability scan complete. Total vulnerabilities found: %d\n", totalVulns)
}

func isVersionExcluded(version string, excludeVersions string) bool {
	excludeList := strings.Split(excludeVersions, ",")
	for _, excludedVersion := range excludeList {
		if version == excludedVersion {
			return true
		}
	}
	return false
}

func queryOSV(pkg config.Package, minSeverity string, verbosity int) error {
	// Simulate querying OSV (replace with actual API interaction)
	if verbosity > 0 {
		fmt.Printf("Simulating OSV query for package %s (version %s)...\n", pkg.Name, pkg.Version)
	}

	// Retry logic in case of failure
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := processQuery(pkg, minSeverity, verbosity)
		if err == nil {
			return nil // Query succeeded
		}
		fmt.Printf("Attempt %d failed: %v\n", attempt, err)
		if attempt < maxRetries {
			time.Sleep(2 * time.Second) // Delay before retrying
		}
	}
	return fmt.Errorf("max retries reached for package %s", pkg.Name)
}

func processQuery(pkg config.Package, minSeverity string, verbosity int) error {
	// Simulated query processing logic (this can be replaced with actual query code)
	vulns := getVulnerabilities(pkg)
	for _, vuln := range vulns {
		if isSeverityMet(vuln.Severity, minSeverity) {
			if verbosity > 1 {
				fmt.Printf("Detailed info: %s - %s\n", vuln.Description, vuln.CVE)
			}
			fmt.Printf("Vulnerability found: %s\n", vuln.Description)
		}
	}
	return nil
}

func isSeverityMet(vulnSeverity string, minSeverity string) bool {
	severities := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}
	return severities[vulnSeverity] >= severities[minSeverity]
}

func getVulnerabilities(pkg config.Package) []report.Vulnerability {
	// Simulate fetching vulnerabilities from OSV for package `pkg`
	return []report.Vulnerability{
		{"golang/gopkg.in/yaml.v3", "High", "CVE-2021-12345 - Description of the vulnerability...", "CVE-2021-12345"},
		{"npm/lodash", "Critical", "CVE-2021-98765 - Description of the vulnerability...", "CVE-2021-98765"},
	}
}

func logError(message string, err error) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s: %v\n", message, err)
}
