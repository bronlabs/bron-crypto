//go:build !purego && !nobignum

package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

func LCM[N internal.NatMutablePtr[N, NT], NT any](out, a, b N) {
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

func GCDAtLeastOneOdd[N internal.NatMutablePtr[N, NT], NT any](out, a, b N) {
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

func GCD[N internal.NatMutablePtr[N, NT], NT any](out, a, b N) {
	var lcm, prod NT
	N(&prod).Mul(a, b)
	LCM(N(&lcm), a, b)

	lcmNonZero := N(&lcm).IsZero().Not()
	var gcdFromFormula, fallback NT
	
	// Fallback for when LCM is zero (i.e., when either input is zero)
	GCDAtLeastOneOdd(N(&fallback), a, b)
	
	// Try division - will succeed only if LCM is non-zero and division is exact
	divOk := N(&gcdFromFormula).DivCap(N(&prod), N(&lcm), -1)
	formulaOk := lcmNonZero & divOk

	// When formula works, use gcdFromFormula; otherwise use fallback
	out.Select(formulaOk, N(&fallback), N(&gcdFromFormula))
}
