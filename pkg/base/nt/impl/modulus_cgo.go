//go:build !purego && !nobignum

package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/cronokirby/saferith"
)

func (m *ModulusOddPrime) ModExp(out, base, exp *Nat) {
	bReduced := new(saferith.Nat).Mod((*saferith.Nat)(base), (*saferith.Modulus)(m))
	bBytes := bReduced.Bytes()
	eBytes := exp.Bytes()
	mBytes := m.Bytes()

	bNum, err := boring.NewBigNum().SetBytes(bBytes)
	if err != nil {
		panic(err)
	}
	eNum, err := boring.NewBigNum().SetBytes(eBytes)
	if err != nil {
		panic(err)
	}
	mNum, err := boring.NewBigNum().SetBytes(mBytes)
	if err != nil {
		panic(err)
	}

	bnCtx := boring.NewBigNumCtx()
	montCtx, err := boring.NewBigNumMontCtx(mNum, bnCtx)
	if err != nil {
		panic(err)
	}
	rNum, err := boring.NewBigNum().Exp(bNum, eNum, mNum, montCtx, bnCtx)
	if err != nil {
		panic(err)
	}
	rBytes, err := rNum.Bytes()
	if err != nil {
		panic(err)
	}
	rNat := new(saferith.Nat).SetBytes(rBytes)
	out.Set((*Nat)(rNat))
}

func (m *ModulusOddPrime) ModMul(out, x, y *Nat) {
	xBytes, yBytes, mBytes := x.Bytes(), y.Bytes(), m.Bytes()

	xNum, err := boring.NewBigNum().SetBytes(xBytes)
	if err != nil {
		panic(err)
	}
	yNum, err := boring.NewBigNum().SetBytes(yBytes)
	if err != nil {
		panic(err)
	}
	mNum, err := boring.NewBigNum().SetBytes(mBytes)
	if err != nil {
		panic(err)
	}

	bnCtx := boring.NewBigNumCtx()
	outNum, err := boring.NewBigNum().ModMul(xNum, yNum, mNum, bnCtx)
	if err != nil {
		panic(err)
	}
	outBytes, err := outNum.Bytes()
	if err != nil {
		panic(err)
	}
	outNat := new(saferith.Nat).SetBytes(outBytes)
	out.Set((*Nat)(outNat))

}
