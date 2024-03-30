package boring_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

func TestBigNum_Jacobi(t *testing.T) {
	// taken from Wikipedia :)
	expected := []int{0, 1, 1, -1, 1, -1, -1, -1, 1, 1, -1, -1, -1, 1, -1, 1, 1}

	y := boring.NewBigNum().SetBytes(new(saferith.Nat).SetUint64(17).Bytes())
	bnCtx := boring.NewBigNumCtx()
	for i := 0; i <= 16; i++ {
		x := boring.NewBigNum().SetBytes(new(saferith.Nat).SetUint64(uint64(i)).Bytes())
		j := x.Jacobi(y, bnCtx)
		require.Equal(t, j, expected[i])
	}
}
