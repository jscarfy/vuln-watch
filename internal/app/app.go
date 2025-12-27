package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/git-store-hub/vuln-watch/internal/config"
	"github.com/git-store-hub/vuln-watch/internal/osv"
	"github.com/git-store-hub/vuln-watch/internal/report"
)

func Run(cfgPath string, out io.Writer, errOut io.Writer) (int, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return 2, err
	}

	client := osv.NewClient(10 * time.Second)

	results := make([]report.PackageResult, 0)

	for _, src := range cfg.Sources {
		for _, pkg := range src.Packages {
			r := report.PackageResult{
				Source:  src.Name,
				ID:      pkg.ID,
				PURL:    pkg.PURL,
				Name:    pkg.Name,
				Ecosystem: pkg.Ecosystem,
			}

			resp, qerr := client.Query(osv.QueryRequest{
				PURL:      strings.TrimSpace(pkg.PURL),
				Ecosystem: strings.TrimSpace(pkg.Ecosystem),
				Name:      strings.TrimSpace(pkg.Name),
				Version:   strings.TrimSpace(pkg.Version),
			})
			if qerr != nil {
				r.Error = qerr.Error()
				results = append(results, r)
				continue
			}

			r.Vulns = resp.Vulns
			results = append(results, r)
		}
	}

	// Output
	switch strings.ToLower(cfg.Output.Format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return 2, err
		}
	default:
		report.PrintText(out, results, cfg)
	}

	// Exit behavior for CI
	hasVuln := report.HasVulnAboveThreshold(results, cfg.Output.MinSeverity)
	if hasVuln && cfg.Output.FailOnVuln {
		fmt.Fprintln(errOut, "vulnerabilities found above threshold; failing as configured")
		return 1, nil
	}

	return 0, nil
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}
