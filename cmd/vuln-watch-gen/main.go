package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jscarfy/vuln-watch/internal/config"
	"github.com/jscarfy/vuln-watch/internal/ingest"
	"gopkg.in/yaml.v3"
)

func main() {
	var gomodPath string
	var outPath string
	var sourceName string
	var includeIndirect bool

	flag.StringVar(&gomodPath, "gomod", "go.mod", "Path to go.mod")
	flag.StringVar(&outPath, "out", "configs/generated.yaml", "Output YAML path")
	flag.StringVar(&sourceName, "source", "gomod", "Source name in generated config")
	flag.BoolVar(&includeIndirect, "include-indirect", false, "Include indirect deps from go.mod")
	flag.Parse()

	deps, err := ingest.ParseGoMod(gomodPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	src := config.Source{Name: sourceName}
	for _, d := range deps {
		if d.Indirect && !includeIndirect {
			continue
		}
		purl, perr := ingest.ToPURL(d)
		if perr != nil {
			continue
		}
		id := strings.ReplaceAll(d.Module, "/", "_")
		id = strings.ReplaceAll(id, ".", "_")
		src.Packages = append(src.Packages, config.Package{
			ID:   id,
			PURL: purl,
		})
	}

	cfg := config.Config{
		Sources: []config.Source{src},
		Output: config.Output{
			Format:      "markdown",
			FailOnVuln:  false,
			MinSeverity: "LOW",
		},
	}

	b, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if err := os.MkdirAll(dirOf(outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	fmt.Println("wrote:", outPath)
	fmt.Printf("deps: %d (include_indirect=%v)\n", len(src.Packages), includeIndirect)
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "."
	}
	return p[:i]
}
