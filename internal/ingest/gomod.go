package ingest

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// GoModDep represents a dependency from go.mod.
type GoModDep struct {
	Module   string
	Version  string
	Indirect bool
}

func ParseGoMod(path string) ([]GoModDep, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(path, b, nil)
	if err != nil {
		return nil, err
	}

	out := make([]GoModDep, 0, len(f.Require))
	for _, r := range f.Require {
		out = append(out, GoModDep{
			Module:   r.Mod.Path,
			Version:  r.Mod.Version,
			Indirect: r.Indirect,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// ToPURL converts a Go module dependency to a purl.
// Spec-ish format used in practice: pkg:golang/<module>@<version>
func ToPURL(d GoModDep) (string, error) {
	if strings.TrimSpace(d.Module) == "" || strings.TrimSpace(d.Version) == "" {
		return "", fmt.Errorf("invalid dep: module or version empty")
	}
	return fmt.Sprintf("pkg:golang/%s@%s", d.Module, d.Version), nil
}
