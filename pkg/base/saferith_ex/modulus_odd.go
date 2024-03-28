package saferith_ex

import (
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

type oddModulus struct {
	boringModulus *boring.BigNum
	montCtx       *boring.BigNumMontCtx
	modulus       *saferith.Modulus
}

func NewOddModulus(modulus *saferith.Nat) (Modulus, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	if modulus.Byte(0)&0b1 != 1 {
		return nil, errs.NewArgument("modulus is not odd")
	}

	m := boring.NewBigNum().SetBytes(modulus.Bytes())
	bnCtx := boring.NewBigNumCtx()
	montCtx := boring.NewBigNumMontCtx(m, bnCtx)

	return &oddModulus{
		boringModulus: m,
		montCtx:       montCtx,
		modulus:       saferith.ModulusFromNat(modulus),
	}, nil
}

func (m *oddModulus) Modulus() *saferith.Modulus {
	return m.modulus
}

func (m *oddModulus) Nat() *saferith.Nat {
	return m.modulus.Nat()
}

func (m *oddModulus) Exp(base, exponent *saferith.Nat) *saferith.Nat {
	bnCtx := boring.NewBigNumCtx()

	b := boring.NewBigNum().SetBytes(base.Bytes())
	bModM := boring.NewBigNum().Mod(b, m.boringModulus, bnCtx)
	e := boring.NewBigNum().SetBytes(exponent.Bytes())
	r := boring.NewBigNum().Exp(bModM, e, m.boringModulus, m.montCtx, bnCtx)

	return new(saferith.Nat).SetBytes(r.Bytes())
}

func (m *oddModulus) MultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) []*saferith.Nat {
	bnCtx := boring.NewBigNumCtx()

	bb := make([]*boring.BigNum, len(bases))
	for i := range bases {
		bi := boring.NewBigNum().SetBytes(bases[i].Bytes())
		bb[i] = boring.NewBigNum().Mod(bi, m.boringModulus, bnCtx)
	}

	ee := boring.NewBigNum().SetBytes(exponent.Bytes())
	rr := make([]*boring.BigNum, len(bb))

	var wg sync.WaitGroup
	jobFunc := func(i int) {
		localCtx := boring.NewBigNumCtx()
		rr[i] = boring.NewBigNum().Exp(bb[i], ee, m.boringModulus, m.montCtx, localCtx)
		wg.Done()
	}

	for i := range bb {
		wg.Add(1)
		go jobFunc(i)
	}
	wg.Wait()

	r := make([]*saferith.Nat, len(rr))
	for i := range rr {
		r[i] = new(saferith.Nat).SetBytes(rr[i].Bytes())
	}
	return r
}

func (m *oddModulus) MultiExponentExp(base *saferith.Nat, exponents []*saferith.Nat) []*saferith.Nat {
	bnCtx := boring.NewBigNumCtx()

	bb := boring.NewBigNum().SetBytes(base.Bytes())
	bm := boring.NewBigNum().Mod(bb, m.boringModulus, bnCtx)
	ee := make([]*boring.BigNum, len(exponents))
	for i := range exponents {
		ee[i] = boring.NewBigNum().SetBytes(exponents[i].Bytes())
	}

	rr := make([]*boring.BigNum, len(ee))

	var wg sync.WaitGroup
	jobFunc := func(i int) {
		localCtx := boring.NewBigNumCtx()
		rr[i] = boring.NewBigNum().Exp(bm, ee[i], m.boringModulus, m.montCtx, localCtx)
		wg.Done()
	}

	for i := range ee {
		wg.Add(1)
		go jobFunc(i)
	}
	wg.Wait()

	r := make([]*saferith.Nat, len(rr))
	for i := range rr {
		r[i] = new(saferith.Nat).SetBytes(rr[i].Bytes())
	}
	return r
}
