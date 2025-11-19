//go:build !purego && !nobignum

package numct

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/cronokirby/saferith"
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

func NewModulus(m *Nat) (*Modulus, ct.Bool) {
	ok := m.IsNonZero()

	defer func() {
		if r := recover(); r != nil {
			ok &= ct.False
		}
	}()

	safeMod := saferith.ModulusFromNat((*saferith.Nat)(m))
	mNum, err := boring.NewBigNum().SetBytes(safeMod.Bytes())
	if err != nil {
		panic(err)
	}

	var mSub2 Nat
	mSub2.SubCap(m, NewNat(2), -1)
	return &Modulus{
		ModulusBasic: (*ModulusBasic)(safeMod),
		mSub2:        &mSub2,
		mNum:         mNum,
		once:         &sync.Once{},
	}, ok
}

type Modulus struct {
	*ModulusBasic
	mSub2 *Nat
	mNum  *boring.BigNum
	mont  *boring.BigNumMontCtx
	once  *sync.Once
}

func (c *Modulus) cacheMont() {
	// use a temporary BN_CTX to build the mont ctx
	tmp := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(tmp)
	mont, err := boring.NewBigNumMontCtx(c.mNum, tmp)
	if err != nil {
		panic(err)
	}
	c.mont = mont
}

func (c *Modulus) ensureMont() {
	if c.mont != nil {
		return
	}
	c.once.Do(func() { c.cacheMont() })
}

func (m *Modulus) modExpOdd(out, base, exp *Nat) {
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

func (m *Modulus) ModExp(out, base, exp *Nat) {
	if m.Nat().IsOdd() == ct.True {
		m.modExpOdd(out, base, exp)
	} else {
		m.ModulusBasic.modExpEven(out, base, exp.Big())
	}
}

func (m *Modulus) modMultiBaseExpOdd(out, bases []*Nat, exp *Nat) {
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

func (m *Modulus) ModMultiBaseExp(out, bases []*Nat, exp *Nat) {
	if len(bases) != len(out) {
		panic("len(bases) != len(out)")
	}
	if m.Nat().IsOdd() == ct.True {
		m.modMultiBaseExpOdd(out, bases, exp)
	} else {
		m.ModulusBasic.ModMultiBaseExp(out, bases, exp)
	}
}

func (m *Modulus) modInvOddPrime(out, a *Nat) ct.Bool {
	m.ensureMont()

	// Reduce a modulo m
	var aReduced Nat
	m.Mod(&aReduced, a)

	ok := aReduced.IsNonZero()

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
	var outCandidate Nat
	outCandidate.SetBytes(invBytes)

	var shouldBeOne Nat
	m.ModMul(&shouldBeOne, &outCandidate, a)

	ok &= shouldBeOne.IsOne()

	out.CondAssign(ok, &outCandidate)
	return ok
}

func (m *Modulus) ModInv(out, a *Nat) ct.Bool {
	ok := a.IsNonZero()
	if m.Nat().IsOdd() == ct.True {
		ok &= m.modInvOddPrime(out, a)
		// This should work only for groups whose almost all of its elements are units. This property of the modulus is not secret.
		if ok == ct.False {
			ok = m.ModulusBasic.modInvOdd(out, a)
		}
	} else {
		ok = m.ModulusBasic.modInvEven(out, a)
	}
	return ok
}

func (m *Modulus) ModMul(out, x, y *Nat) {
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

func (m *Modulus) Set(v *Modulus) {
	m.ModulusBasic.Set(v.ModulusBasic)
	m.mSub2 = v.mSub2
	m.mNum = v.mNum
	m.mont = v.mont
	m.once = v.once
}

func (m *Modulus) SetNat(n *Nat) ct.Bool {
	mm, ok := NewModulus(n)
	if mm != nil {
		*m = *mm
	}
	return ok
}
