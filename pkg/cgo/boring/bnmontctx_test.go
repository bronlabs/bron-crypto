//go:build !purego && !nobignum

package boring_test

import (
	"runtime"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/cgo/boring"
)

func Test_Sanity(t *testing.T) {
	xNat := new(saferith.Nat).SetUint64(11)
	xNum, err := boring.NewBigNum().SetBytes(xNat.Bytes())
	require.NoError(t, err)

	bnCtx := boring.NewBigNumCtx()
	_, err = boring.NewBigNumMontCtx(xNum, bnCtx)
	require.NoError(t, err)

	runtime.GC()
}

func Test_NoCopy(t *testing.T) {
	xNat := new(saferith.Nat).SetUint64(11)
	xNum, _ := boring.NewBigNum().SetBytes(xNat.Bytes())
	bnCtx := boring.NewBigNumCtx()
	montCtx, _ := boring.NewBigNumMontCtx(xNum, bnCtx)

	montCtxCopy := *montCtx
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	_, _ = boring.NewBigNum().Exp(boring.One, boring.One, boring.One, &montCtxCopy, bnCtx)
}
