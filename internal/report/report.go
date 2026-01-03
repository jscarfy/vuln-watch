package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

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

		visible := filterVisible(r.Vulns, onlyNew)
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
			score := MaxScore(mv)
			scoreStr := ""
			if score > 0 {
				scoreStr = fmt.Sprintf(" (score=%.1f)", score)
			}
			fmt.Fprintf(w, "    - %s%s%s: %s\n", v.ID, tag, scoreStr, oneLine(v.Summary))
		}
	}

	fmt.Fprintln(w, "\n------------------------------------------------------------")
	fmt.Fprintln(w, "TIP: Use --state to persist seen vulns; use --only-new=false to show everything.")
	fmt.Fprintln(w, "TIP: Set output.fail_on_vuln=true to use in CI gating.")
}

func PrintMarkdown(w io.Writer, results []PackageResult, cfg *config.Config, onlyNew bool) {
	now := time.Now().UTC().Format(time.RFC3339)
	minLabel := strings.ToUpper(cfg.Output.MinSeverity)

	fmt.Fprintf(w, "# vuln-watch report\n\n")
	fmt.Fprintf(w, "- generated: `%s`\n", now)
	fmt.Fprintf(w, "- min_severity: `%s`\n", minLabel)
	fmt.Fprintf(w, "- only_new: `%v`\n\n", onlyNew)

	allVisible := 0
	allNew := 0
	aboveThreshold := 0
	newAboveThreshold := 0

	for _, r := range results {
		visible := filterVisible(r.Vulns, onlyNew)
		allVisible += len(visible)
		for _, mv := range visible {
			if mv.IsNew {
				allNew++
			}
			if MeetsThreshold(mv, minLabel) {
				aboveThreshold++
				if mv.IsNew {
					newAboveThreshold++
				}
			}
		}
	}

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "- visible vulns: **%d**\n", allVisible)
	fmt.Fprintf(w, "- visible NEW vulns: **%d**\n", allNew)
	fmt.Fprintf(w, "- visible vulns >= `%s`: **%d**\n", minLabel, aboveThreshold)
	fmt.Fprintf(w, "- visible NEW vulns >= `%s`: **%d**\n\n", minLabel, newAboveThreshold)

	// Package table
	type row struct {
		Source string
		Pkg    string
		Count  int
		NewCnt int
		Above  int
		Ref    string
		Error  string
	}
	rows := make([]row, 0, len(results))

	for _, r := range results {
		visible := filterVisible(r.Vulns, onlyNew)
		newCnt := 0
		above := 0
		for _, mv := range visible {
			if mv.IsNew {
				newCnt++
			}
			if MeetsThreshold(mv, minLabel) {
				above++
			}
		}

		pkg := r.ID
		if pkg == "" {
			pkg = r.Name
		}
		ref := r.PURL
		if ref == "" && r.Name != "" {
			ref = r.Ecosystem + "/" + r.Name
		}

		rows = append(rows, row{
			Source: r.Source,
			Pkg:    pkg,
			Count:  len(visible),
			NewCnt: newCnt,
			Above:  above,
			Ref:    ref,
			Error:  r.Error,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].NewCnt != rows[j].NewCnt {
			return rows[i].NewCnt > rows[j].NewCnt
		}
		if rows[i].Above != rows[j].Above {
			return rows[i].Above > rows[j].Above
		}
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		return rows[i].Pkg < rows[j].Pkg
	})

	fmt.Fprintf(w, "## Packages\n\n")
	fmt.Fprintf(w, "| source | package | visible | new | >= %s | ref | status |\n", minLabel)
	fmt.Fprintf(w, "|---|---:|---:|---:|---:|---|---|\n")
	for _, r := range rows {
		status := "ok"
		if r.Error != "" {
			status = "error"
		}
		fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %s | %s |\n",
			escapePipe(r.Source),
			escapePipe(r.Pkg),
			r.Count,
			r.NewCnt,
			r.Above,
			escapePipe(r.Ref),
			escapePipe(status),
		)
	}

	// NEW-ONLY detail section (diff-like)
	fmt.Fprintf(w, "\n## NEW vulnerabilities\n\n")
	newAny := false
	for _, pr := range results {
		if pr.Error != "" {
			continue
		}
		newVs := make([]MarkedVuln, 0)
		for _, mv := range pr.Vulns {
			if mv.IsNew && (!onlyNew || mv.IsNew) {
				newVs = append(newVs, mv)
			}
		}
		if len(newVs) == 0 {
			continue
		}
		newAny = true
		title := pr.ID
		if title == "" {
			title = pr.Name
		}
		fmt.Fprintf(w, "### %s\n\n", escapeMD(title))
		if pr.PURL != "" {
			fmt.Fprintf(w, "- purl: `%s`\n\n", pr.PURL)
		} else {
			fmt.Fprintf(w, "- pkg: `%s/%s`\n\n", pr.Ecosystem, pr.Name)
		}
		for _, mv := range newVs {
			v := mv.Vuln
			score := MaxScore(mv)
			scoreStr := ""
			if score > 0 {
				scoreStr = fmt.Sprintf(" (score=%.1f)", score)
			}
			th := ""
			if MeetsThreshold(mv, minLabel) {
				th = " ✅"
			} else {
				th = " ⚪"
			}
			fmt.Fprintf(w, "- `%s`%s — %s%s\n", v.ID, scoreStr, escapeMD(oneLine(v.Summary)), th)
		}
		fmt.Fprintln(w, "")
	}
	if !newAny {
		fmt.Fprintf(w, "_No new vulnerabilities detected._\n\n")
	}

	// Full details (visible set)
	fmt.Fprintf(w, "## Details (visible)\n\n")
	for _, pr := range results {
		visible := filterVisible(pr.Vulns, onlyNew)
		if pr.Error != "" || len(visible) == 0 {
			continue
		}
		title := pr.ID
		if title == "" {
			title = pr.Name
		}
		fmt.Fprintf(w, "### %s\n\n", escapeMD(title))
		if pr.PURL != "" {
			fmt.Fprintf(w, "- purl: `%s`\n\n", pr.PURL)
		} else {
			fmt.Fprintf(w, "- pkg: `%s/%s`\n\n", pr.Ecosystem, pr.Name)
		}
		for _, mv := range visible {
			v := mv.Vuln
			tag := ""
			if mv.IsNew {
				tag = " **(NEW)**"
			}
			score := MaxScore(mv)
			scoreStr := ""
			if score > 0 {
				scoreStr = fmt.Sprintf(" (score=%.1f)", score)
			}
			th := ""
			if MeetsThreshold(mv, minLabel) {
				th = " ✅"
			} else {
				th = " ⚪"
			}
			fmt.Fprintf(w, "- `%s`%s%s — %s%s\n", v.ID, tag, scoreStr, escapeMD(oneLine(v.Summary)), th)
		}
		fmt.Fprintln(w, "")
	}
}

func filterVisible(vs []MarkedVuln, onlyNew bool) []MarkedVuln {
	visible := make([]MarkedVuln, 0, len(vs))
	for _, mv := range vs {
		if onlyNew && !mv.IsNew {
			continue
		}
		visible = append(visible, mv)
	}
	return visible
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func escapePipe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
