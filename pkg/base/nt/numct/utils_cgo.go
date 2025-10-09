//go:build !purego && !nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
)

func LCM(out, a, b *Nat) {
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

func GCDAtLeastOneOdd(out, a, b *Nat) {
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
	outNum, err := boring.NewBigNum().Gcd(aNum, bNum, bnCtx)
	if err != nil {
		panic(err)
	}
	outBytes, err := outNum.Bytes()
	if err != nil {
		panic(err)
	}
	out.SetBytes(outBytes)
}

func GCD(out, a, b *Nat) {
	var ab, lcm Nat
	ab.Mul(a, b)
	LCM(&lcm, a, b)
	denom, _ := NewModulus(&lcm)
	out.DivCap(&ab, denom, -1)
}
