package report

import (
	"math"
	"strings"

	"github.com/jscarfy/vuln-watch/internal/severity"
)

// MaxScore returns the max parsed severity score among severity entries (if any).
// If no numeric score can be parsed, returns 0.
func MaxScore(v MarkedVuln) float64 {
	max := 0.0
	for _, s := range v.Vuln.Severity {
		score := strings.TrimSpace(s.Score)
		if val, ok := severity.ParseCVSSScore(score); ok {
			if val > max {
				max = val
			}
		}
		// Some feeds may put numeric in Type or other formats; keep it simple for now.
	}
	// clamp
	if max < 0 {
		return 0
	}
	if max > 10 {
		return 10
	}
	// Normalize tiny floats
	if math.Abs(max) < 1e-9 {
		return 0
	}
	return max
}

func MeetsThreshold(v MarkedVuln, minLabel string) bool {
	min := severity.ThresholdLabelToMinScore(minLabel)

	score := MaxScore(v)
	if score == 0 {
		// No numeric score available -> treat as meets threshold if threshold is LOW
		// (so you still see stuff), but not for MEDIUM+.
		return strings.ToUpper(strings.TrimSpace(minLabel)) == "LOW"
	}
	return score >= min
}

func HasAnyVulnAbove(results []PackageResult, minLabel string) bool {
	for _, r := range results {
		for _, mv := range r.Vulns {
			if MeetsThreshold(mv, minLabel) {
				return true
			}
		}
	}
	return false
}

func HasNewVulnAbove(results []PackageResult, minLabel string) bool {
	for _, r := range results {
		for _, mv := range r.Vulns {
			if mv.IsNew && MeetsThreshold(mv, minLabel) {
				return true
			}
		}
	}
	return false
}
