package affect

import (
	"strings"

	"golang.org/x/mod/semver"
)

// OSV-style affected range events:
// https://ossf.github.io/osv-schema/#affectedrangesevent-fields
//
// We implement a best-effort evaluator for the "ECOSYSTEM" range type,
// using semver comparison for Go versions.
//
// NOTE: OSV versions for Go modules typically start with "v" (v1.2.3).
// We'll normalize by ensuring the "v" prefix.

type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Range struct {
	Type   string       `json:"type,omitempty"`
	Events []RangeEvent `json:"events,omitempty"`
}

type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem,omitempty"`
		Name      string `json:"name,omitempty"`
		PURL      string `json:"purl,omitempty"`
	} `json:"package,omitempty"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// AffectedByRanges returns true if version appears affected by any provided ranges.
// If ranges are absent, returns false (unknown).
func AffectedByRanges(version string, ranges []Range) bool {
	v := norm(version)
	if v == "" || !semver.IsValid(v) {
		return false
	}
	for _, r := range ranges {
		if strings.ToUpper(r.Type) != "ECOSYSTEM" {
			continue
		}
		if affectedByEcosystemRange(v, r.Events) {
			return true
		}
	}
	return false
}

// AffectedByVersionsList returns true if version is explicitly listed in OSV "versions".
func AffectedByVersionsList(version string, versions []string) bool {
	v := norm(version)
	if v == "" {
		return false
	}
	for _, x := range versions {
		if norm(x) == v {
			return true
		}
	}
	return false
}

func affectedByEcosystemRange(v string, events []RangeEvent) bool {
	// OSV events represent alternating introduced/fixed boundaries.
	// Common patterns:
	// - introduced: "0" (meaning "all versions from start") then fixed: "1.2.3"
	// - introduced: "1.0.0" then fixed: "1.2.3"
	// - introduced: "1.0.0" then last_affected: "1.1.9" (no fixed)
	//
	// We'll treat segments:
	//   [introduced, fixed) as affected
	//   [introduced, last_affected] as affected
	//
	// If multiple introduced/fixed pairs exist, any segment match => affected.

	introduced := ""
	for _, e := range events {
		if e.Introduced != "" {
			introduced = e.Introduced
			continue
		}
		if introduced == "" {
			continue
		}

		if e.Fixed != "" {
			lo := introduced
			hi := e.Fixed
			if inHalfOpen(v, lo, hi) {
				return true
			}
			introduced = ""
			continue
		}

		if e.LastAffected != "" {
			lo := introduced
			hi := e.LastAffected
			if inClosed(v, lo, hi) {
				return true
			}
			introduced = ""
			continue
		}
	}
	return false
}

func inHalfOpen(v, lo, hi string) bool {
	// [lo, hi)
	// lo can be "0" meaning "from beginning"
	if lo == "0" || lo == "" {
		lo = "v0.0.0"
	}
	lo = norm(lo)
	hi = norm(hi)
	if !semver.IsValid(lo) || !semver.IsValid(hi) {
		return false
	}
	return semver.Compare(v, lo) >= 0 && semver.Compare(v, hi) < 0
}

func inClosed(v, lo, hi string) bool {
	// [lo, hi]
	if lo == "0" || lo == "" {
		lo = "v0.0.0"
	}
	lo = norm(lo)
	hi = norm(hi)
	if !semver.IsValid(lo) || !semver.IsValid(hi) {
		return false
	}
	return semver.Compare(v, lo) >= 0 && semver.Compare(v, hi) <= 0
}

func norm(s string) string {
	x := strings.TrimSpace(s)
	if x == "" {
		return ""
	}
	// OSV sometimes stores "1.2.3" without "v"
	if x != "0" && !strings.HasPrefix(x, "v") {
		x = "v" + x
	}
	return x
}
