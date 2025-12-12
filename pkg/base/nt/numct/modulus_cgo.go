//go:build !purego && !nobignum

package numct

import (
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
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

// NewModulus creates a new Modulus from a Nat.
// It returns ok = false if m is zero.
// Remarks: it leaks the true length of m.
func NewModulus(m *Nat) (modulus *Modulus, ok ct.Bool) {
	ok = m.IsNonZero()

	defer func() { // saferith panics on zero modulus.
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
	return &Modulus{ //nolint:exhaustruct // mont is not precomputed here for performance.
		ModulusBasic: (*ModulusBasic)(safeMod),
		mSub2:        &mSub2,
		mNum:         mNum,
		once:         &sync.Once{},
	}, ok
}

// Modulus is a modulus implementation based on BoringSSL's BigNum and saferith.Modulus.
type Modulus struct {
	*ModulusBasic

	mSub2 *Nat
	mNum  *boring.BigNum
	mont  *boring.BigNumMontCtx
	once  *sync.Once
}

func (m *Modulus) cacheMont() {
	// use a temporary BN_CTX to build the mont ctx
	tmp, _ := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(tmp)
	mont, err := boring.NewBigNumMontCtx(m.mNum, tmp)
	if err != nil {
		panic(err)
	}
	m.mont = mont
}

func (m *Modulus) ensureMont() {
	if m.mont != nil {
		return
	}
	m.once.Do(func() { m.cacheMont() })
}

func (m *Modulus) modExpOdd(out, base, exp *Nat) {
	m.ensureMont()
	m.Mod(out, base)

	bBytes := out.Bytes()
	eBytes := exp.Bytes()

	bNum, _ := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(bNum)
	if _, err := bNum.SetBytes(bBytes); err != nil {
		panic(err)
	}

	eNum, _ := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(eNum)
	if _, err := eNum.SetBytes(eBytes); err != nil {
		panic(err)
	}

	ctx, _ := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(ctx)

	rNum, _ := bnPool.Get().(*boring.BigNum)
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

// ModExp sets out = base^exp (mod m).
func (m *Modulus) ModExp(out, base, exp *Nat) {
	if m.Nat().IsOdd() == ct.True {
		m.modExpOdd(out, base, exp)
	} else {
		m.ModulusBasic.modExpEven(out, base, exp.Big())
	}
}

func (m *Modulus) modExpIOdd(out, base *Nat, exp *Int) {
	var expAbs, candidate Nat
	expAbs.Abs(exp)
	m.modExpOdd(&candidate, base, &expAbs)

	isNeg := exp.IsNegative()

	var candidateInv Nat
	m.ModInv(&candidateInv, &candidate)

	out.Select(isNeg, &candidate, &candidateInv)
}

// ModExpI sets out = base^exp (mod m) where exp is an Int.
func (m *Modulus) ModExpI(out, base *Nat, exp *Int) {
	if m.Nat().IsOdd() == ct.True {
		m.modExpIOdd(out, base, exp)
	} else {
		m.ModulusBasic.modExpEven(out, base, exp.Big())
	}
}

func (m *Modulus) modMultiBaseExpOdd(out, bases []*Nat, exp *Nat) {
	m.ensureMont()

	eBytes := exp.Bytes()
	eNum, _ := bnPool.Get().(*boring.BigNum)
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
			biNum, _ := bnPool.Get().(*boring.BigNum)
			defer bnPool.Put(biNum)
			if _, err := biNum.SetBytes(biBytes); err != nil {
				panic(err)
			}
			ctx, _ := bnCtxPool.Get().(*boring.BigNumCtx)
			defer bnCtxPool.Put(ctx)

			rNum, _ := bnPool.Get().(*boring.BigNum)
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

// ModMultiBaseExp sets out[i] = bases[i]^exp (mod m) for all i.
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

	if ok == ct.False { // boringssl panics on zero input
		return ok
	}

	aNum, _ := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(aNum)
	if _, err := aNum.SetBytes(aReduced.Bytes()); err != nil {
		panic(err)
	}

	ctx, _ := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(ctx)

	invNum, _ := bnPool.Get().(*boring.BigNum)
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

// ModInv sets out = a^{-1} (mod m).
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

// ModMul sets out = (x * y) (mod m).
func (m *Modulus) ModMul(out, x, y *Nat) {
	xBytes, yBytes := x.Bytes(), y.Bytes()

	xNum, _ := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(xNum)
	if _, err := xNum.SetBytes(xBytes); err != nil {
		panic(err)
	}

	yNum, _ := bnPool.Get().(*boring.BigNum)
	defer bnPool.Put(yNum)
	if _, err := yNum.SetBytes(yBytes); err != nil {
		panic(err)
	}

	bnCtx, _ := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(bnCtx)

	outNum, _ := bnPool.Get().(*boring.BigNum)
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

// Set sets m = v.
func (m *Modulus) Set(v *Modulus) {
	m.ModulusBasic.Set(v.ModulusBasic)
	m.mSub2 = v.mSub2.Clone()
	m.mNum = v.mNum
	m.mont = v.mont
	m.once = v.once
}

// SetNat sets m = n where n is a Nat.
func (m *Modulus) SetNat(n *Nat) ct.Bool {
	mm, ok := NewModulus(n)
	if mm != nil {
		*m = *mm
	}
	return ok
}
