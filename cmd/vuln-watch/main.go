package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/git-store-hub/vuln-watch/internal/app"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "configs/example.yaml", "Path to config YAML")
	flag.Parse()

	code, err := app.Run(cfgPath, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}
