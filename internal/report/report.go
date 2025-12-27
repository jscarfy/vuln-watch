package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/git-store-hub/vuln-watch/internal/config"
	"github.com/git-store-hub/vuln-watch/internal/osv"
)

type PackageResult struct {
	Source    string     `json:"source"`
	ID        string     `json:"id"`
	PURL      string     `json:"purl,omitempty"`
	Ecosystem string     `json:"ecosystem,omitempty"`
	Name      string     `json:"name,omitempty"`

	Vulns []osv.Vuln `json:"vulns,omitempty"`
	Error string     `json:"error,omitempty"`
}

func PrintText(w io.Writer, results []PackageResult, cfg *config.Config) {
	fmt.Fprintf(w, "vuln-watch report (min_severity=%s)\n", strings.ToUpper(cfg.Output.MinSeverity))
	fmt.Fprintln(w, "------------------------------------------------------------")
	for _, r := range results {
		label := r.ID
		if label == "" {
			label = r.Name
		}
		fmt.Fprintf(w, "\n[%s] source=%s\n", label, r.Source)
		if r.PURL != "" {
			fmt.Fprintf(w, "  purl: %s\n", r.PURL)
		} else {
			fmt.Fprintf(w, "  pkg:  %s/%s\n", r.Ecosystem, r.Name)
		}
		if r.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", r.Error)
			continue
		}
		if len(r.Vulns) == 0 {
			fmt.Fprintln(w, "  vulns: none")
			continue
		}
		fmt.Fprintf(w, "  vulns: %d\n", len(r.Vulns))
		for _, v := range r.Vulns {
			fmt.Fprintf(w, "    - %s: %s\n", v.ID, oneLine(v.Summary))
		}
	}
	fmt.Fprintln(w, "\n------------------------------------------------------------")
	fmt.Fprintln(w, "TIP: set output.fail_on_vuln=true to use in CI gating.")
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func HasVulnAboveThreshold(results []PackageResult, minSeverity string) bool {
	// MVP: OSV severity scoring formats vary (CVSS vectors, etc.).
	// For now: treat "any vuln exists" as above threshold.
	// TODO: parse CVSS and compare against configured threshold.
	_ = minSeverity
	for _, r := range results {
		if len(r.Vulns) > 0 {
			return true
		}
	}
	return false
}
