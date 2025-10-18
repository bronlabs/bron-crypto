//go:build !purego && !nobignum

package numct

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

var (
	_ (Modulus) = (*ModulusOddPrime)(nil)
	_ (Modulus) = (*ModulusOdd)(nil)
	_ (Modulus) = (*ModulusBasic)(nil)
)

var bnCtxPool = sync.Pool{
	New: func() any {
		return boring.NewBigNumCtx()
	},
}

var bnPool = sync.Pool{
	New: func() any {
		return boring.NewBigNum()
	},
}

// **************** Modulus Odd Prime ********************

func NewModulusOddPrime(m *Nat) (*ModulusOddPrime, ct.Bool) {
	ok := m.IsProbablyPrime() & m.IsOdd() & m.IsNonZero()

	safeMod := newModulusOddPrimeBasic(m)
	mNum, err := boring.NewBigNum().SetBytes(safeMod.Bytes())
	if err != nil {
		panic(err)
	}

	var mSub2 Nat
	mSub2.SubCap(m, NewNat(2), -1)
	return &ModulusOddPrime{
		ModulusOddPrimeBasic: *safeMod,
		mSub2:                &mSub2,
		mNum:                 mNum,
		once:                 &sync.Once{},
	}, ok
}

type ModulusOddPrime struct {
	ModulusOddPrimeBasic
	mSub2 *Nat
	mNum  *boring.BigNum
	mont  *boring.BigNumMontCtx
	once  *sync.Once
}

func (c *ModulusOddPrime) cacheMont() {
	// use a temporary BN_CTX to build the mont ctx
	tmp := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(tmp)
	mont, err := boring.NewBigNumMontCtx(c.mNum, tmp)
	if err != nil {
		panic(err)
	}
	c.mont = mont
}

func (c *ModulusOddPrime) ensureMont() {
	if c.mont != nil {
		return
	}
	c.once.Do(func() { c.cacheMont() })
}

func (m *ModulusOddPrime) ModExp(out, base, exp *Nat) {
	m.ensureMont()
	m.Mod(out, base)

	bBytes := out.Bytes()
	eBytes := exp.Bytes()

	bNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(bNum)
	if _, err := bNum.SetBytes(bBytes); err != nil {
		panic(err)
	}

	eNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(eNum)
	if _, err := eNum.SetBytes(eBytes); err != nil {
		panic(err)
	}

	ctx := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(ctx)

	rNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(rNum)
	if _, err := rNum.Exp(bNum, eNum, m.mNum, m.mont, ctx); err != nil {
		panic(err)
	}

	rBytes, err := rNum.Bytes()
	if err != nil {
		panic(err)
	}
	out.SetBytes(rBytes)
}

func (m *ModulusOddPrime) ModMultiBaseExp(out, bases []*Nat, exp *Nat) {
	if len(bases) != len(out) {
		panic("len(bases) != len(out)")
	}
	m.ensureMont()

	eBytes := exp.Bytes()
	eNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(eNum)
	if _, err := eNum.SetBytes(eBytes); err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	wg.Add(len(bases))
	for i, bi := range bases {
		go func(i int) {
			defer wg.Done()

			m.Mod(out[i], bi)
			biBytes := out[i].Bytes()
			biNum := bnPool.Get().(*boring.BigNum)
			defer bnPool.Put(biNum)
			if _, err := biNum.SetBytes(biBytes); err != nil {
				panic(err)
			}
			ctx := bnCtxPool.Get().(*boring.BigNumCtx)
			defer bnCtxPool.Put(ctx)

			rNum := bnPool.Get().(*boring.BigNum)
			defer bnPool.Put(rNum)
			if _, err := rNum.Exp(biNum, eNum, m.mNum, m.mont, ctx); err != nil {
				panic(err)
			}
			rBytes, err := rNum.Bytes()
			if err != nil {
				panic(err)
			}
			out[i].SetBytes(rBytes)
		}(i)
	}
	wg.Wait()
}

func (m *ModulusOddPrime) ModInv(out, a *Nat) ct.Bool {
	// mm := newModulusOddBasic(m.Nat())
	// return mm.ModInv(out, a)

	m.ensureMont()

	// Reduce a modulo m
	var aReduced Nat
	m.Mod(&aReduced, a)

	aNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(aNum)
	if _, err := aNum.SetBytes(aReduced.Bytes()); err != nil {
		panic(err)
	}

	ctx := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(ctx)

	invNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(invNum)
	_, noInverse, err := invNum.Inv(aNum, m.mont, ctx)
	// If noInverse is set, this is expected (not an error condition)
	if noInverse != 0 {
		return ct.False
	}
	// Any other error is unexpected
	if err != nil {
		panic(err)
	}
	invBytes, err := invNum.Bytes()
	if err != nil {
		panic(err)
	}
	out.SetBytes(invBytes)
	return ct.True
}

func (m *ModulusOddPrime) ModMul(out, x, y *Nat) {
	// m.ModulusOddPrimeBasic.ModMul(out, x, y)
	// return

	xBytes, yBytes := x.Bytes(), y.Bytes()

	xNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(xNum)
	if _, err := xNum.SetBytes(xBytes); err != nil {
		panic(err)
	}

	yNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(yNum)
	if _, err := yNum.SetBytes(yBytes); err != nil {
		panic(err)
	}

	bnCtx := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(bnCtx)

	outNum := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(outNum)
	if _, err := outNum.ModMul(xNum, yNum, m.mNum, bnCtx); err != nil {
		panic(err)
	}

	outBytes, err := outNum.Bytes()
	if err != nil {
		panic(err)
	}
	out.SetBytes(outBytes)
}

func (m *ModulusOddPrime) Set(v *ModulusOddPrime) {
	m.ModulusOddPrimeBasic.Set(&v.ModulusOddPrimeBasic)
	m.mNum = v.mNum
	m.mont = v.mont
}

func (m *ModulusOddPrime) SetNat(n *Nat) ct.Bool {
	mm, ok := NewModulusOddPrime(n)
	m.Set(mm)
	return ok
}

// ********************* Modulus Odd

func NewModulusOdd(m *Nat) (*ModulusOdd, ct.Bool) {
	mm, _ := NewModulusOddPrime(m)  // Always creates the structure
	ok := m.IsOdd() & m.IsNonZero() // Check if it's odd and non-zero
	return &ModulusOdd{
		ModulusOddPrime: *mm,
	}, ok
}

type ModulusOdd struct {
	ModulusOddPrime
}

func (m *ModulusOdd) Set(v *ModulusOdd) {
	m.ModulusOddPrime.Set(&v.ModulusOddPrime)
}

func (m *ModulusOdd) SetNat(n *Nat) ct.Bool {
	mm, ok := NewModulusOdd(n)
	m.Set(mm)
	return ok
}

func (m *ModulusOdd) ModSqrt(out, x *Nat) ct.Bool {
	return (&ModulusOddBasic{
		ModulusOddPrimeBasic: m.ModulusOddPrimeBasic,
	}).ModSqrt(out, x)
}

func (m *ModulusOdd) ModInv(out, x *Nat) ct.Bool {
	mm := newModulusOddBasic(m.Nat())
	return mm.ModInv(out, x)
}

// ******************** Generic Modulus

type ModulusNonZero = ModulusBasic

func NewModulusNonZero(m *Nat) (*ModulusNonZero, ct.Bool) {
	ok := m.IsNonZero()
	return newModulusBasic(m), ok
}
