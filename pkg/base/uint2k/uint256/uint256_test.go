package uint256_test

import (
	"testing"

	"github.com/bronlabs/krypton-primitives/pkg/base/uint2k/uint256"
)

func TestUint256Constants(t *testing.T) {
	t.Parallel()
	u := uint256.Max.AddUint64(1)
	if !u.IsZero() {
		t.Fatalf("Max + 1 should equal 0, got %v", u)
	}
	u = uint256.Zero.SubUint64(1)
	if !u.Equal(uint256.Max) {
		t.Fatalf("Min - 1 should equal Max, got %v", u)
	}
}
