package severity

import "testing"

func TestThresholdLabelToMinScore(t *testing.T) {
	if ThresholdLabelToMinScore("LOW") != 0.1 {
		t.Fatal("LOW threshold mismatch")
	}
	if ThresholdLabelToMinScore("MEDIUM") != 4.0 {
		t.Fatal("MEDIUM threshold mismatch")
	}
	if ThresholdLabelToMinScore("HIGH") != 7.0 {
		t.Fatal("HIGH threshold mismatch")
	}
	if ThresholdLabelToMinScore("CRITICAL") != 9.0 {
		t.Fatal("CRITICAL threshold mismatch")
	}
}

func TestParseCVSSScoreNumeric(t *testing.T) {
	if v, ok := ParseCVSSScore("9.8"); !ok || v != 9.8 {
		t.Fatalf("expected 9.8 true, got %v %v", v, ok)
	}
}

func TestParseCVSSScoreHeuristic(t *testing.T) {
	if v, ok := ParseCVSSScore("CVSS:3.1/... score=7.5 ..."); !ok || v != 7.5 {
		t.Fatalf("expected 7.5 true, got %v %v", v, ok)
	}
	if v, ok := ParseCVSSScore("blah SCORE: 4.3"); !ok || v != 4.3 {
		t.Fatalf("expected 4.3 true, got %v %v", v, ok)
	}
}

func TestParseCVSSScoreVectorOnly(t *testing.T) {
	if v, ok := ParseCVSSScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); ok || v != 0 {
		t.Fatalf("expected 0 false, got %v %v", v, ok)
	}
}
