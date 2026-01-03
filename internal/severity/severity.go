package severity

import (
	"strconv"
	"strings"
)

// ThresholdLabelToMinScore maps user labels to numeric CVSS score thresholds.
// Common interpretation:
//
//	LOW      >= 0.1
//	MEDIUM   >= 4.0
//	HIGH     >= 7.0
//	CRITICAL >= 9.0
func ThresholdLabelToMinScore(label string) float64 {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.0
	case "MEDIUM":
		return 4.0
	case "LOW":
		return 0.1
	default:
		return 0.1
	}
}

// ParseCVSSScore attempts to parse a numeric CVSS score from a string.
// Accepted:
//   - pure numeric strings: "9.8"
//   - strings containing "score=<num>" or "score:<num>" (case-insensitive), e.g.
//     "CVSS:3.1/... score=7.5 ..."
//     "blah SCORE: 4.3"
//
// NOTE: A CVSS vector like "CVSS:3.1/AV:N/..." does not contain the score by itself,
// so we return (0,false) in that case (unless a numeric score is also embedded).
func ParseCVSSScore(s string) (float64, bool) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, false
	}

	// Numeric direct
	if v, err := strconv.ParseFloat(raw, 64); err == nil {
		return v, true
	}

	l := strings.ToLower(raw)

	// score=
	if i := strings.Index(l, "score="); i >= 0 {
		tail := raw[i+len("score="):]
		tail = strings.TrimSpace(tail)
		tail = cutAtDelims(tail)
		tail = strings.TrimSpace(tail)
		if v, err := strconv.ParseFloat(tail, 64); err == nil {
			return v, true
		}
	}

	// score:
	if i := strings.Index(l, "score:"); i >= 0 {
		tail := raw[i+len("score:"):]
		tail = strings.TrimSpace(tail)
		tail = cutAtDelims(tail)
		tail = strings.TrimSpace(tail)
		if v, err := strconv.ParseFloat(tail, 64); err == nil {
			return v, true
		}
	}

	return 0, false
}

func cutAtDelims(s string) string {
	// Expect s already trimmed. Cut at first delimiter AFTER the number.
	for _, d := range []string{",", ";", " ", "\n", "\t"} {
		if j := strings.Index(s, d); j >= 0 {
			return s[:j]
		}
	}
	return s
}
