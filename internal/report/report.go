package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jscarfy/vuln-watch/internal/config"
	"github.com/jscarfy/vuln-watch/internal/osv"
)

type MarkedVuln struct {
	Vuln  osv.Vuln `json:"vuln"`
	IsNew bool     `json:"is_new"`
}

type PackageResult struct {
	Source    string `json:"source"`
	ID        string `json:"id"`
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`

	Vulns []MarkedVuln `json:"vulns,omitempty"`
	Error string       `json:"error,omitempty"`
}

func StateKey(sourceName string, pkg any) string {
	// Keep it stable: prefer PURL if present; otherwise ecosystem+name.
	// pkg is expected to be config.Package, but we avoid import cycles by using reflection-free string formatting elsewhere.
	// We reconstruct key in app using ID+fields, so this is only used there via helper that accepts config.Package.
	return sourceName + "::" + fmt.Sprintf("%v", pkg)
}

func PrintText(w io.Writer, results []PackageResult, cfg *config.Config, onlyNew bool) {
	fmt.Fprintf(w, "vuln-watch report (min_severity=%s, only_new=%v)\n", strings.ToUpper(cfg.Output.MinSeverity), onlyNew)
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

		visible := make([]MarkedVuln, 0, len(r.Vulns))
		for _, mv := range r.Vulns {
			if onlyNew && !mv.IsNew {
				continue
			}
			visible = append(visible, mv)
		}

		if len(visible) == 0 {
			if len(r.Vulns) == 0 {
				fmt.Fprintln(w, "  vulns: none")
			} else if onlyNew {
				fmt.Fprintln(w, "  vulns: none new (already seen)")
			} else {
				fmt.Fprintln(w, "  vulns: none")
			}
			continue
		}

		fmt.Fprintf(w, "  vulns: %d\n", len(visible))
		for _, mv := range visible {
			v := mv.Vuln
			tag := ""
			if mv.IsNew {
				tag = " [NEW]"
			}
			fmt.Fprintf(w, "    - %s%s: %s\n", v.ID, tag, oneLine(v.Summary))
		}
	}

	fmt.Fprintln(w, "\n------------------------------------------------------------")
	fmt.Fprintln(w, "TIP: Use --state to persist seen vulns; use --only-new=false to show everything.")
	fmt.Fprintln(w, "TIP: Set output.fail_on_vuln=true to use in CI gating.")
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

// MVP thresholding: treat any vuln as "above threshold" until we implement robust scoring.
// Keep the threshold parameter for forward compatibility.
func HasAnyVuln(results []PackageResult, _ string) bool {
	for _, r := range results {
		if len(r.Vulns) > 0 {
			return true
		}
	}
	return false
}

func HasNewVuln(results []PackageResult, _ string) bool {
	for _, r := range results {
		for _, mv := range r.Vulns {
			if mv.IsNew {
				return true
			}
		}
	}
	return false
}
