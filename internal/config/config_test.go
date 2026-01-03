package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	tmp := t.TempDir()
	p := tmp + "/cfg.yaml"
	if err := os.WriteFile(p, []byte(`
sources:
  - name: "x"
    packages:
      - id: "a"
        purl: "pkg:golang/example.com/a@v1.0.0"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output.Format != "text" {
		t.Fatalf("expected default format text, got %q", cfg.Output.Format)
	}
	if cfg.Output.MinSeverity != "LOW" {
		t.Fatalf("expected default severity LOW, got %q", cfg.Output.MinSeverity)
	}
}
