package report

import (
	"strings"

	"github.com/jscarfy/vuln-watch/internal/config"
)

func StableKey(sourceName string, p config.Package) string {
	// Prefer PURL because it is globally unique.
	if strings.TrimSpace(p.PURL) != "" {
		return sourceName + "::purl::" + strings.TrimSpace(p.PURL)
	}
	eco := strings.TrimSpace(p.Ecosystem)
	name := strings.TrimSpace(p.Name)
	ver := strings.TrimSpace(p.Version)
	if ver != "" {
		return sourceName + "::pkg::" + eco + "::" + name + "::" + ver
	}
	return sourceName + "::pkg::" + eco + "::" + name
}
