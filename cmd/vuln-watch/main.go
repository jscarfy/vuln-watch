package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/git-store-hub/vuln-watch/internal/app"
)

func main() {
	var cfgPath string
	var statePath string
	var onlyNew bool
	var writeState bool

	flag.StringVar(&cfgPath, "config", "configs/example.yaml", "Path to config YAML")
	flag.StringVar(&statePath, "state", ".vuln-watch/state.json", "Path to state JSON (stores last seen vuln IDs)")
	flag.BoolVar(&onlyNew, "only-new", true, "Only show newly discovered vulnerabilities compared to state")
	flag.BoolVar(&writeState, "write-state", true, "Write updated state after run")
	flag.Parse()

	opts := app.Options{
		ConfigPath: cfgPath,
		StatePath:  statePath,
		OnlyNew:    onlyNew,
		WriteState: writeState,
	}

	code, err := app.Run(opts, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}
