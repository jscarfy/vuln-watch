package affect

import "testing"

func TestAffectedByVersionsList(t *testing.T) {
	if !AffectedByVersionsList("v1.2.3", []string{"v1.2.3"}) {
		t.Fatal("expected match")
	}
	if AffectedByVersionsList("v1.2.4", []string{"v1.2.3"}) {
		t.Fatal("expected no match")
	}
	if !AffectedByVersionsList("1.2.3", []string{"v1.2.3"}) {
		t.Fatal("expected normalization match")
	}
}

func TestAffectedByRangesHalfOpen(t *testing.T) {
	r := []Range{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "0"},
			{Fixed: "1.2.0"},
		},
	}}
	if !AffectedByRanges("v1.1.9", r) {
		t.Fatal("expected affected")
	}
	if AffectedByRanges("v1.2.0", r) {
		t.Fatal("expected not affected at fixed boundary")
	}
}

func TestAffectedByRangesClosed(t *testing.T) {
	r := []Range{{
		Type: "ECOSYSTEM",
		Events: []RangeEvent{
			{Introduced: "1.0.0"},
			{LastAffected: "1.1.0"},
		},
	}}
	if !AffectedByRanges("v1.1.0", r) {
		t.Fatal("expected affected at last_affected")
	}
	if AffectedByRanges("v1.1.1", r) {
		t.Fatal("expected not affected")
	}
}
