//go:build !purego && !nobignum

package boring_test

import (
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/cgo/boring"
)

func TestBigNum_Jacobi(t *testing.T) {
	// taken from Wikipedia :)
	expected := []int{0, 1, 1, -1, 1, -1, -1, -1, 1, 1, -1, -1, -1, 1, -1, 1, 1}

	y, err := boring.NewBigNum().SetBytes(new(saferith.Nat).SetUint64(17).Bytes())
	require.NoError(t, err)
	bnCtx := boring.NewBigNumCtx()
	for i := 0; i <= 16; i++ {
		x, err := boring.NewBigNum().SetBytes(new(saferith.Nat).SetUint64(uint64(i)).Bytes())
		require.NoError(t, err)
		j, err := x.Jacobi(y, bnCtx)
		require.NoError(t, err)
		require.Equal(t, j, expected[i])
	}
}

func TestBigNum_Error(t *testing.T) {
	zero, err := new(boring.BigNum).SetBytes([]byte{0})
	require.NoError(t, err)
	ctx := boring.NewBigNumCtx()
	_, err = new(boring.BigNum).Mod(zero, zero, ctx)
	require.True(t, strings.Contains(err.Error(), "DIV_BY_ZERO"))
}
