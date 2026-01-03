package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jscarfy/vuln-watch/internal/affect"
	"github.com/jscarfy/vuln-watch/internal/config"
	"github.com/jscarfy/vuln-watch/internal/osv"
	"github.com/jscarfy/vuln-watch/internal/report"
	"github.com/jscarfy/vuln-watch/internal/state"
)

type Options struct {
	ConfigPath string
	StatePath  string
	OnlyNew    bool
	WriteState bool
	OutPath    string // "" => stdout
	Explain    string // package id to explain (optional)
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

			targetVersion := strings.TrimSpace(pkg.Version)
			if targetVersion == "" {
				targetVersion = affect.ExtractPURLVersion(pkg.PURL)
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

			for _, v := range resp.Vulns {
				keep := true
				expl := ""

				// Version-aware filtering (best-effort)
				if targetVersion != "" && len(v.Affected) > 0 {
					keep = false
					unknown := true

					for _, a := range v.Affected {
						// If versions list is present and matches -> affected
						if len(a.Versions) > 0 {
							unknown = false
							if affect.AffectedByVersionsList(targetVersion, a.Versions) {
								keep = true
								expl = "affected: versions list"
								break
							}
						}
						// Else ranges check
						if len(a.Ranges) > 0 {
							unknown = false
							rs := make([]affect.Range, 0, len(a.Ranges))
							for _, rr := range a.Ranges {
								evs := make([]affect.RangeEvent, 0, len(rr.Events))
								for _, e := range rr.Events {
									evs = append(evs, affect.RangeEvent{Introduced: e.Introduced, Fixed: e.Fixed, LastAffected: e.LastAffected})
								}
								rs = append(rs, affect.Range{Type: rr.Type, Events: evs})
							}
							if affect.AffectedByRanges(targetVersion, rs) {
								keep = true
								expl = "affected: ecosystem ranges"
								break
							}
						}
					}

					// If we can't interpret affected data, keep (conservative)
					if !keep && unknown {
						keep = true
						expl = "affected: unknown (kept)"
					}
				}

				if !keep {
					if opts.Explain != "" && opts.Explain == pkg.ID {
						fmt.Fprintf(errOut, "EXPLAIN drop: pkg=%s vuln=%s version=%s\n", pkg.ID, v.ID, targetVersion)
					}
					continue
				}

				isNew := !st.IsSeen(key, v.ID)
				r.Vulns = append(r.Vulns, report.MarkedVuln{Vuln: v, IsNew: isNew})

				if opts.Explain != "" && opts.Explain == pkg.ID {
					fmt.Fprintf(errOut, "EXPLAIN keep: pkg=%s vuln=%s version=%s %s\n", pkg.ID, v.ID, targetVersion, expl)
				}

				st.MarkSeen(key, v.ID)
			}

			results = append(results, r)
		}
	}

	// Choose output writer
	w := out
	var f *os.File
	if strings.TrimSpace(opts.OutPath) != "" {
		ff, ferr := os.Create(opts.OutPath)
		if ferr != nil {
			return 2, ferr
		}
		f = ff
		defer f.Close()
		w = f
	}

	switch strings.ToLower(cfg.Output.Format) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return 2, err
		}
	case "markdown", "md":
		report.PrintMarkdown(w, results, cfg, opts.OnlyNew)
	default:
		report.PrintText(w, results, cfg, opts.OnlyNew)
	}

	if opts.WriteState {
		if err := state.Save(opts.StatePath, st); err != nil {
			return 2, err
		}
	}

	var hasGateVuln bool
	if opts.OnlyNew {
		hasGateVuln = report.HasNewVulnAbove(results, cfg.Output.MinSeverity)
	} else {
		hasGateVuln = report.HasAnyVulnAbove(results, cfg.Output.MinSeverity)
	}

	if hasGateVuln && cfg.Output.FailOnVuln {
		fmt.Fprintln(errOut, "vulnerabilities found above threshold; failing as configured")
		return 1, nil
	}

	return 0, nil
}
