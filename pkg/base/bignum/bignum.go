package bignum

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum/internal/impl"
	"github.com/cronokirby/saferith"
	"sync"
)

func FastPrimeGen(bits int) *saferith.Nat {
	xx := impl.InitBigNum(&impl.BoringBigNum{}).GenPrime(bits, 0)
	defer impl.FreeBigNum(xx)

	return new(saferith.Nat).SetBytes(xx.Bytes())
}

func FastExp(x, y, m *saferith.Nat) *saferith.Nat {
	bnCtx := impl.NewBigNumCtx()
	defer impl.FreeBigNumCtx(bnCtx)

	mm := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(m.Bytes())
	defer impl.FreeBigNum(mm)

	montCtx := impl.NewMontCtx(mm, bnCtx)
	defer impl.FreeMontCtx(montCtx)

	xx := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(x.Bytes())
	defer impl.FreeBigNum(xx)

	yy := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(y.Bytes())
	defer impl.FreeBigNum(yy)

	xm := impl.InitBigNum(&impl.BoringBigNum{}).Mod(xx, mm, bnCtx)
	defer impl.FreeBigNum(xm)

	rr := impl.InitBigNum(&impl.BoringBigNum{}).Exp(xm, yy, mm, montCtx, bnCtx)
	defer impl.FreeBigNum(rr)

	return new(saferith.Nat).SetBytes(rr.Bytes())
}

func FastFixedBaseMultiExp(base *saferith.Nat, exponent []*saferith.Nat, modulus *saferith.Nat) []*saferith.Nat {
	bnCtx := impl.NewBigNumCtx()
	defer impl.FreeBigNumCtx(bnCtx)

	bb := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(base.Bytes())
	defer impl.FreeBigNum(bb)

	mm := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(modulus.Bytes())
	defer impl.FreeBigNum(mm)

	montCtx := impl.NewMontCtx(mm, bnCtx)
	defer impl.FreeMontCtx(montCtx)

	bm := impl.InitBigNum(&impl.BoringBigNum{}).Mod(bb, mm, bnCtx)
	defer impl.FreeBigNum(bm)

	ee := make([]impl.BoringBigNum, len(exponent))
	for i := range exponent {
		impl.InitBigNum(&ee[i]).SetBytes(exponent[i].Bytes())
	}
	defer func() {
		for i := range exponent {
			impl.FreeBigNum(&ee[i])
		}
	}()

	rr := make([]impl.BoringBigNum, len(exponent))
	for i := range ee {
		impl.InitBigNum(&rr[i])
	}
	defer func() {
		for i := range rr {
			impl.FreeBigNum(&rr[i])
		}
	}()

	var wg sync.WaitGroup
	jobFunc := func(i int) {
		localCtx := impl.NewBigNumCtx()
		defer impl.FreeBigNumCtx(localCtx)
		rr[i].Exp(bb, &ee[i], mm, montCtx, localCtx)
		wg.Done()
	}

	for i := range exponent {
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

func FastFixedExponentMultiExp(base []*saferith.Nat, exponent, modulus *saferith.Nat) []*saferith.Nat {
	bnCtx := impl.NewBigNumCtx()
	defer impl.FreeBigNumCtx(bnCtx)

	mm := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(modulus.Bytes())
	defer impl.FreeBigNum(mm)

	montCtx := impl.NewMontCtx(mm, bnCtx)
	defer impl.FreeMontCtx(montCtx)

	bb := make([]impl.BoringBigNum, len(base))
	for i := range base {
		bi := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(base[i].Bytes())
		impl.InitBigNum(&bb[i]).Mod(bi, mm, bnCtx)
		impl.FreeBigNum(bi)
	}
	defer func() {
		for i := range bb {
			impl.FreeBigNum(&bb[i])
		}
	}()

	ee := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(exponent.Bytes())
	defer impl.FreeBigNum(ee)

	rr := make([]impl.BoringBigNum, len(bb))
	for i := range bb {
		impl.InitBigNum(&rr[i])
	}
	defer func() {
		for i := range rr {
			impl.FreeBigNum(&rr[i])
		}
	}()

	var wg sync.WaitGroup
	jobFunc := func(i int) {
		localCtx := impl.NewBigNumCtx()
		defer impl.FreeBigNumCtx(localCtx)
		rr[i].Exp(&bb[i], ee, mm, montCtx, localCtx)
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
