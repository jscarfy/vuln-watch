package state

import "testing"

func TestNewEmpty(t *testing.T) {
	s := New()
	if s.Seen == nil || len(s.Seen) != 0 {
		t.Fatalf("expected empty seen map")
	}
}
