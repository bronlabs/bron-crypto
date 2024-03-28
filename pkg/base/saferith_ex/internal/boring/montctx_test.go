package boring_test

import (
	"runtime"
	"testing"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

func Test_Sanity(t *testing.T) {
	xNat := new(saferith.Nat).SetUint64(11)
	xNum := boring.NewBigNum().SetBytes(xNat.Bytes())
	bnCtx := boring.NewBigNumCtx()
	_ = boring.NewBigNumMontCtx(xNum, bnCtx)

	runtime.GC()
}

func Test_NoCopy(t *testing.T) {
	// This test passes but govet won't allow to compile it.
	// If you know how to ignore govet linter for the test you can uncomment lines below

	//xNat := new(saferith.Nat).SetUint64(11)
	//xNum := boring.NewBigNum().SetBytes(xNat.Bytes())
	//bnCtx := boring.NewBigNumCtx()
	//montCtx := boring.NewBigNumMontCtx(xNum, bnCtx)

	//montCtxCopy := *montCtx
	//defer func() {
	//	if r := recover(); r == nil {
	//		t.Errorf("The code did not panic")
	//	}
	//}()
	//_ = boring.NewBigNum().Exp(boring.One, boring.One, boring.One, &montCtxCopy, bnCtx)
}
