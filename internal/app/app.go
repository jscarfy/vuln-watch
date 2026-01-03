package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/git-store-hub/vuln-watch/internal/config"
	"github.com/git-store-hub/vuln-watch/internal/osv"
	"github.com/git-store-hub/vuln-watch/internal/report"
	"github.com/git-store-hub/vuln-watch/internal/state"
)

type Options struct {
	ConfigPath string
	StatePath  string
	OnlyNew    bool
	WriteState bool
}

func Run(opts Options, out io.Writer, errOut io.Writer) (int, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return 2, err
	}

	st, err := state.Load(opts.StatePath)
	if err != nil {
		return 2, err
	}

	client := osv.NewClient(10 * time.Second)
	results := make([]report.PackageResult, 0)

	for _, src := range cfg.Sources {
		for _, pkg := range src.Packages {
			key := report.StableKey(src.Name, pkg)

			r := report.PackageResult{
				Source:    src.Name,
				ID:        pkg.ID,
				PURL:      pkg.PURL,
				Name:      pkg.Name,
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

			// Compute "new" vulns vs state
			for _, v := range resp.Vulns {
				isNew := !st.IsSeen(key, v.ID)
				r.Vulns = append(r.Vulns, report.MarkedVuln{Vuln: v, IsNew: isNew})

				// Always mark as seen in updated state (regardless of output filtering)
				st.MarkSeen(key, v.ID)
			}

			results = append(results, r)
		}
	}

	// Output
	switch strings.ToLower(cfg.Output.Format) {
	case "json":
		type jsonPkg struct {
			Source    string              `json:"source"`
			ID        string              `json:"id"`
			PURL      string              `json:"purl,omitempty"`
			Ecosystem string              `json:"ecosystem,omitempty"`
			Name      string              `json:"name,omitempty"`
			Vulns     []report.MarkedVuln `json:"vulns,omitempty"`
			Error     string              `json:"error,omitempty"`
		}
		j := make([]jsonPkg, 0, len(results))
		for _, r := range results {
			j = append(j, jsonPkg{
				Source:    r.Source,
				ID:        r.ID,
				PURL:      r.PURL,
				Ecosystem: r.Ecosystem,
				Name:      r.Name,
				Vulns:     r.Vulns,
				Error:     r.Error,
			})
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(j); err != nil {
			return 2, err
		}
	default:
		report.PrintText(out, results, cfg, opts.OnlyNew)
	}

	// Write state (optional)
	if opts.WriteState {
		if err := state.Save(opts.StatePath, st); err != nil {
			return 2, err
		}
	}

	// Exit behavior for CI:
	// If "only-new" is enabled, gate only on newly discovered vulns.
	var hasGateVuln bool
	if opts.OnlyNew {
		hasGateVuln = report.HasNewVuln(results, cfg.Output.MinSeverity)
	} else {
		hasGateVuln = report.HasAnyVuln(results, cfg.Output.MinSeverity)
	}

	if hasGateVuln && cfg.Output.FailOnVuln {
		fmt.Fprintln(errOut, "vulnerabilities found above threshold; failing as configured")
		return 1, nil
	}

	return 0, nil
}
