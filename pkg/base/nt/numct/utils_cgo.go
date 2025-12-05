//go:build !purego && !nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func LCM(out, a, b *Nat) {
	if a.IsZero()|b.IsZero() == ct.True {
		out.SetZero()
		return
	}
	aBytes, bBytes := a.Bytes(), b.Bytes()
	aNum, err := boring.NewBigNum().SetBytes(aBytes)
	if err != nil {
		panic(err)
	}
	bNum, err := boring.NewBigNum().SetBytes(bBytes)
	if err != nil {
		panic(err)
	}
	bnCtx := boring.NewBigNumCtx()
	outNum, err := boring.NewBigNum().Lcm(aNum, bNum, bnCtx)
	if err != nil {
		panic(err)
	}
	outBytes, err := outNum.Bytes()
	if err != nil {
		panic(err)
	}
	out.SetBytes(outBytes)
}
