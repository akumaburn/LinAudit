package procmon

import "testing"

// TestRound1Parity locks round1 to round-half-to-even (banker's rounding),
// matching Python's round(x, 1). See review finding procmon-round-1. The half
// cases below are exactly representable in float64, so the tie-breaking rule is
// what is under test.
func TestRound1Parity(t *testing.T) {
	cases := []struct {
		in, want float64
	}{
		{6.25, 6.2},   // tie -> even
		{0.25, 0.2},   // tie -> even
		{2.25, 2.2},   // tie -> even
		{0.75, 0.8},   // tie -> even
		{72.44, 72.4}, // round down
		{72.46, 72.5}, // round up
		{0, 0},
		{100, 100},
	}
	for _, c := range cases {
		if got := round1(c.in); got != c.want {
			t.Errorf("round1(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
