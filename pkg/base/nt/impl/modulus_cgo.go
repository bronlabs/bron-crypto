//go:build !purego && !nobignum

package impl

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/cronokirby/saferith"
)

var (
	_ (internal.ModulusMutable[*Nat]) = (*ModulusOddPrime)(nil)
	_ (internal.ModulusMutable[*Nat]) = (*ModulusOdd)(nil)
	_ (internal.ModulusMutable[*Nat]) = (*Modulus)(nil)
)

var bnCtxPool = sync.Pool{
	New: func() any {
		return boring.NewBigNumCtx()
	},
}

// **************** Modulus Odd Prime ********************

func NewModulusOddPrime(m *Nat) (*ModulusOddPrime, ct.Bool) {
	ok := m.IsProbablyPrime() & m.IsOdd() & m.IsNonZero()

	var mEff Nat
	mEff.CondAssign(ok, NewNat(3), m)
	safeMod := (*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(m)))
	mNum, err := boring.NewBigNum().SetBytes(safeMod.Bytes())
	if err != nil {
		panic(err)
	}
	return &ModulusOddPrime{
		ModulusOddPrimeBasic: *safeMod,
		mNum:                 mNum,
		once:                 &sync.Once{},
	}, ok
}

type ModulusOddPrime struct {
	ModulusOddPrimeBasic
	mNum *boring.BigNum
	mont *boring.BigNumMontCtx
	once *sync.Once
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
	var bReduced Nat
	m.Mod(&bReduced, base)

	bBytes := bReduced.Bytes()
	eBytes := exp.Bytes()

	bNum, err := boring.NewBigNum().SetBytes(bBytes)
	if err != nil {
		panic(err)
	}
	eNum, err := boring.NewBigNum().SetBytes(eBytes)
	if err != nil {
		panic(err)
	}

	ctx := bnCtxPool.Get().(*boring.BigNumCtx)
	defer bnCtxPool.Put(ctx)

	rNum, err := boring.NewBigNum().Exp(bNum, eNum, m.mNum, m.mont, ctx)
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

func (m *ModulusOddPrime) Set(v *ModulusOddPrime) {
	m.ModulusOddPrimeBasic.Set(&v.ModulusOddPrimeBasic)
	m.mNum = v.mNum
	m.mont = v.mont
}

func (m *ModulusOddPrime) SetNat(n *Nat) ct.Bool {
	// Only return false if n is zero
	if n.IsZero() == ct.True {
		return ct.False
	}

	ok := m.ModulusOddPrimeBasic.SetNat(n)
	// Only set up Montgomery context if the number is actually odd and prime
	if ok == ct.True && n.IsOdd() == ct.True && n.IsProbablyPrime() == ct.True {
		mNum, err := boring.NewBigNum().SetBytes(m.Bytes())
		if err != nil {
			panic(err)
		}
		m.mNum = mNum
		// Initialize once if it's nil
		if m.once == nil {
			m.once = &sync.Once{}
		}
		m.cacheMont()
	}
	return ok
}

// ********************* Modulus Odd

func NewModulusOdd(m *Nat) (*ModulusOdd, ct.Bool) {
	ok := m.IsOdd() & m.IsNonZero()

	// For odd non-primes, we still need to create the structure
	// but we'll use a safe fallback for the Montgomery context
	safeMod := (*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(m)))
	mNum, err := boring.NewBigNum().SetBytes(safeMod.Bytes())
	if err != nil {
		panic(err)
	}

	return &ModulusOdd{
		ModulusOddPrime: ModulusOddPrime{
			ModulusOddPrimeBasic: *safeMod,
			mNum:                 mNum,
			once:                 &sync.Once{},
		},
		forSqrt: &ModulusOddBasic{
			ModulusOddPrimeBasic: *safeMod,
		},
	}, ok
}

type ModulusOdd struct {
	ModulusOddPrime
	forSqrt *ModulusOddBasic
}

func (m *ModulusOdd) Set(v *ModulusOdd) {
	m.ModulusOddPrime.Set(&v.ModulusOddPrime)
	m.forSqrt.Set(v.forSqrt)
}

func (m *ModulusOdd) SetNat(n *Nat) ct.Bool {
	// Only return false if n is zero
	if n.IsZero() == ct.True {
		return ct.False
	}

	// For ModulusOdd (non-prime), we need to set up the basic structure
	// but NOT try to create a Montgomery context for non-primes
	ok := n.IsNonZero()
	
	// Set the basic modulus structure
	safeMod := (*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(n)))
	m.ModulusOddPrime.ModulusOddPrimeBasic = *safeMod
	
	// Set up the BigNum but NOT the Montgomery context (since n might not be prime)
	mNum, err := boring.NewBigNum().SetBytes(safeMod.Bytes())
	if err != nil {
		panic(err)
	}
	m.ModulusOddPrime.mNum = mNum
	
	// Initialize once to non-nil so we don't panic
	if m.ModulusOddPrime.once == nil {
		m.ModulusOddPrime.once = &sync.Once{}
	}
	// Don't call cacheMont for non-primes - leave mont as nil
	
	// Initialize forSqrt if it's nil
	if m.forSqrt == nil {
		m.forSqrt = &ModulusOddBasic{
			ModulusOddPrimeBasic: m.ModulusOddPrime.ModulusOddPrimeBasic,
		}
	} else {
		ok &= m.forSqrt.SetNat(n)
	}
	return ok
}

// ******************** Generic Modulus

type Modulus = ModulusBasic

func NewModulus(m *Nat) (*Modulus, ct.Bool) {
	ok := m.IsNonZero()
	var mEff Nat
	mEff.CondAssign(ok, NewNat(3), m)
	return newModulusBasic(&mEff), ok
}
