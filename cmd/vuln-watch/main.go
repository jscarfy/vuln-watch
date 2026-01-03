package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jscarfy/vuln-watch/internal/app"
)

func main() {
	var cfgPath string
	var statePath string
	var onlyNew bool
	var writeState bool
	var outPath string
	var explain string

	flag.StringVar(&cfgPath, "config", "configs/example.yaml", "Path to config YAML")
	flag.StringVar(&statePath, "state", ".vuln-watch/state.json", "Path to state JSON (stores last seen vuln IDs)")
	flag.BoolVar(&onlyNew, "only-new", true, "Only show newly discovered vulnerabilities compared to state")
	flag.BoolVar(&writeState, "write-state", true, "Write updated state after run")
	flag.StringVar(&outPath, "out", "", "Write report to file (default: stdout)")
	flag.StringVar(&explain, "explain", "", "Explain keep/drop decisions for a package id (prints to stderr)")
	flag.Parse()

	opts := app.Options{
		ConfigPath: cfgPath,
		StatePath:  statePath,
		OnlyNew:    onlyNew,
		WriteState: writeState,
		OutPath:    outPath,
		Explain:    explain,
	}

	code, err := app.Run(opts, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}
