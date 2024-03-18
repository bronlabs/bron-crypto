package uint256_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/uint2k/uint256"
)

func TestUint256Constants(t *testing.T) {
	ring256 := uint256.Ring()
	u := ring256.Top().AddUint64(1)
	if !u.IsZero() {
		t.Fatalf("Max + 1 should equal 0, got %v", u)
	}
	u = ring256.Bottom().SubUint64(1)
	if !u.Equal(ring256.Top()) {
		t.Fatalf("Min - 1 should equal Max, got %v", u)
	}
}
