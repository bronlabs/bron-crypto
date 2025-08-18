package impl

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/cronokirby/saferith"
)

var (
	_ (internal.ModulusMutable[*Nat]) = (*ModulusOddPrime)(nil)
	_ (internal.ModulusMutable[*Nat]) = (*ModulusOdd)(nil)
	_ (internal.ModulusMutable[*Nat]) = (*Modulus)(nil)
)

func NewModulusFromNat(m *Nat) internal.ModulusMutable[*Nat] {
	mNat := (*saferith.Nat)(m)
	safeMod := saferith.ModulusFromNat(mNat)
	modulusIsPrime := (*Nat)(mNat).IsProbablyPrime()
	modulusIsOdd := (*Nat)(mNat).IsOdd()

	v := (*ModulusOddPrime)(safeMod)
	vv := &ModulusOdd{ModulusOddPrime: *v}
	vvv := &Modulus{ModulusOdd: *vv}

	// If odd and prime, return ModulusOddPrime
	if modulusIsOdd&modulusIsPrime == ct.True {
		return v
	}
	// If odd but not prime, return ModulusOdd
	if modulusIsOdd == ct.True {
		return vv
	}
	// Otherwise (even), return Modulus
	return vvv
}

type (
	ModulusOddPrime saferith.Modulus
	ModulusOdd      struct {
		ModulusOddPrime
	}
	Modulus struct {
		ModulusOdd
	}
)

func (m *ModulusOddPrime) Clone() *ModulusOddPrime {
	return (*ModulusOddPrime)(saferith.ModulusFromNat((*saferith.Nat)(m.Nat())))
}

func (m *ModulusOddPrime) Set(v *ModulusOddPrime) {
	*m = *v
}

func (m *ModulusOddPrime) Mod(out, x *Nat) {
	(*saferith.Nat)(out).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

func (m *ModulusOddPrime) ModAdd(out, x, y *Nat) {
	(*saferith.Nat)(out).ModAdd(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrime) ModSub(out, x, y *Nat) {
	(*saferith.Nat)(out).ModSub(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrime) ModDiv(out, x, y *Nat) {
	// Division in modular arithmetic: x/y = x * y^(-1) mod m
	yInv := new(saferith.Nat)
	yInv.ModInverse((*saferith.Nat)(y), (*saferith.Modulus)(m))
	(*saferith.Nat)(out).ModMul((*saferith.Nat)(x), yInv, (*saferith.Modulus)(m))
}

func (m *ModulusOddPrime) ModInv(out, x *Nat) ct.Bool {
	(*saferith.Nat)(out).ModInverse(
		(*saferith.Nat)(x),
		(*saferith.Modulus)(m),
	)
	return m.Nat().IsOdd() & x.Coprime(m.Nat())
}

func (m *ModulusOddPrime) Neg(out, x *Nat) {
	(*saferith.Nat)(out).ModNeg((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

func (m *ModulusOddPrime) ModSqrt(out, x *Nat) ct.Bool {
	// Reduce x modulo m to avoid mutating caller inputs and ensure range.
	xr := (*Nat)(new(saferith.Nat).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m)))

	// Compute Legendre symbol (x|m) in CT w.r.t. x using Euler's criterion.
	j := LegendreSymbol(m, xr) // ∈ {-1,0,1}

	// ok if x ≡ 0 (mod m) OR j == 1.
	isZero := ct.Bool((*saferith.Nat)(xr).EqZero())
	jIsOne := ct.IsZero(uint8(j) ^ 1) // 1 iff j == 1
	ok := isZero | jIsOne

	// Compute candidate root unconditionally (algorithm depends only on modulus).
	root := new(saferith.Nat).ModSqrt((*saferith.Nat)(xr), (*saferith.Modulus)(m))

	// Constant-time conditional assignment into out.
	out.CondAssign(ok, out, (*Nat)(root))
	return ok
}

func (m *ModulusOddPrime) InRange(x *Nat) ct.Bool {
	// x is in range if 0 <= x < m
	// Cmp returns (>, =, <) in that order
	_, _, lt := (*saferith.Nat)(x).Cmp((*saferith.Modulus)(m).Nat())
	return ct.Bool(lt)
}

func (m *ModulusOddPrime) IsUnit(x *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(x).IsUnit((*saferith.Modulus)(m)))
}

func (m *ModulusOddPrime) BitLen() uint {
	return uint((*saferith.Modulus)(m).BitLen())
}

func (m *ModulusOddPrime) Nat() *Nat {
	return (*Nat)((*saferith.Modulus)(m).Nat())
}

func (m *ModulusOddPrime) SetNat(n *Nat) ct.Bool {
	v := saferith.ModulusFromNat((*saferith.Nat)(n))
	*m = *(*ModulusOddPrime)(v)
	return n.IsNonZero() & m.Nat().IsOdd() & n.IsProbablyPrime()
}

func (m *ModulusOddPrime) Bytes() []byte {
	return (*saferith.Modulus)(m).Bytes()
}

func (m *ModulusOddPrime) String() string {
	return (*saferith.Modulus)(m).String()
}

// ********* Odd Composite Modulus ************

func (m *ModulusOdd) Clone() *ModulusOdd {
	v := (*ModulusOddPrime)(saferith.ModulusFromNat((*saferith.Nat)(m.Nat())))
	return &ModulusOdd{ModulusOddPrime: *v}
}

func (m *ModulusOdd) Set(v *ModulusOdd) {
	*m = *v
}

func (m *ModulusOdd) SetNat(n *Nat) ct.Bool {
	ok := n.IsNonZero()
	// Use a safe fallback value when n is zero to avoid panic
	safeN := n.Clone()
	one := (*Nat)(new(saferith.Nat).SetUint64(3).Resize(64)) // Use 3 as safe odd modulus
	safeN.CondAssign(ok, one, n)
	
	v := (*ModulusOddPrime)(saferith.ModulusFromNat((*saferith.Nat)(safeN)))
	m.ModulusOddPrime = *v
	return ok
}

func (m *Modulus) ModSqrt(out, x *Nat) ct.Bool {
	reducedXBig := new(saferith.Nat).Mod((*saferith.Nat)(x), (*saferith.Modulus)(&m.ModulusOddPrime)).Big()
	res := new(big.Int).Sqrt(reducedXBig)
	squaredRes := new(big.Int).Mul(res, res)
	if squaredRes.Cmp(reducedXBig) != 0 {
		return ct.False
	}
	// Use the modulus bitlen for consistency
	bitlen := (*saferith.Modulus)(&m.ModulusOddPrime).BitLen()
	out.Set((*Nat)(new(saferith.Nat).SetBig(res, bitlen)))
	return ct.True
}

// ********* Generic Modulus *****************

func (m *Modulus) Clone() *Modulus {
	v := (*ModulusOddPrime)(saferith.ModulusFromNat((*saferith.Nat)(m.Nat())))
	return &Modulus{
		ModulusOdd: ModulusOdd{ModulusOddPrime: *v},
	}
}

func (m *Modulus) ModInv(out, x *Nat) ct.Bool {
	ok := x.IsNonZero() & x.Coprime(m.Nat())
	if ok == ct.True {
		(*saferith.Nat)(out).SetBig(
			new(big.Int).ModInverse((*saferith.Nat)(x).Big(), (*saferith.Modulus)(&m.ModulusOddPrime).Big()),
			(*saferith.Modulus)(&m.ModulusOddPrime).BitLen(),
		)
	}
	return ok
}

func (m *Modulus) Set(v *Modulus) {
	*m = *v
}

func (m *Modulus) SetNat(n *Nat) ct.Bool {
	v := (*ModulusOddPrime)(saferith.ModulusFromNat((*saferith.Nat)(n)))
	vv := &ModulusOdd{ModulusOddPrime: *v}
	m.ModulusOdd = *vv
	return n.IsNonZero()
}

func (m *Modulus) ModExp(out, base, exp *Nat) {
	// For even moduli (like 2), we can't use Montgomery multiplication
	// Use big.Int instead
	baseBig := (*saferith.Nat)(base).Big()
	expBig := (*saferith.Nat)(exp).Big()
	modBig := (*saferith.Modulus)(&m.ModulusOddPrime).Big()

	result := new(big.Int).Exp(baseBig, expBig, modBig)
	bitlen := (*saferith.Modulus)(&m.ModulusOddPrime).BitLen()
	(*saferith.Nat)(out).SetBig(result, bitlen)
}
