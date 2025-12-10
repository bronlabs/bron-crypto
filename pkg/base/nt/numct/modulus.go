package numct

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

// ModulusBasic is a modulus implementation based on saferith.Modulus.
type ModulusBasic saferith.Modulus

// NewModulus creates a new Modulus from a Nat.
func NewModulusFromBytesBE(input []byte) (modulus *Modulus, ok ct.Bool) {
	n := NewNatFromBytes(input)
	return NewModulus(n)
}

// HashCode returns a hash code for the modulus.
func (m *ModulusBasic) HashCode() base.HashCode {
	return base.DeriveHashCode(m.Bytes())
}

// Random returns a random Nat in [0, m).
func (m *ModulusBasic) Random(prng io.Reader) (*Nat, error) {
	randBig, err := crand.Int(prng, m.Big())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return NewNatFromBig(randBig, m.BitLen()), nil
}

// Big returns the big.Int representation of the modulus.
func (m *ModulusBasic) Big() *big.Int {
	return (*saferith.Modulus)(m).Big()
}

// Saferith returns the underlying saferith.Modulus.
func (m *ModulusBasic) Saferith() *saferith.Modulus {
	return (*saferith.Modulus)(m)
}

// Set sets m = v.
func (m *ModulusBasic) Set(v *ModulusBasic) {
	*m = *v
}

// Mod sets out = x (mod m).
func (m *ModulusBasic) Mod(out, x *Nat) {
	(*saferith.Nat)(out).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

// ModI sets out = x (mod m) where x is an Int.
func (m *ModulusBasic) ModI(out *Nat, x *Int) {
	result := (*saferith.Int)(x).Mod((*saferith.Modulus)(m))
	*out = *(*Nat)(result)
}

// ModSymmetric sets out = x mod m in the symmetric range [-m/2, m/2).
func (m *ModulusBasic) ModSymmetric(out *Int, x *Nat) {
	(*saferith.Int)(out).SetModSymmetric((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

// Quo sets out = x / m.
func (m *ModulusBasic) Quo(out, x *Nat) {
	(*saferith.Nat)(out).Div(
		(*saferith.Nat)(x),
		(*saferith.Modulus)(m),
		m.BitLen(),
	)
}

// ModAdd sets out = (x + y) (mod m).
func (m *ModulusBasic) ModAdd(out, x, y *Nat) {
	(*saferith.Nat)(out).ModAdd(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

// ModSub sets out = (x - y) (mod m).
func (m *ModulusBasic) ModSub(out, x, y *Nat) {
	(*saferith.Nat)(out).ModSub(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusBasic) modDivOdd(out, x, y *Nat) ct.Bool {
	ok := y.IsNonZero()
	var yr Nat
	yr.Select(ok, NatOne(), y)

	// inv = y^{-1} mod m
	var yInv Nat
	m.ModInv(&yInv, &yr)

	// out = x * inv mod m
	var prod Nat
	m.ModMul(&prod, x, &yInv)

	out.Select(ok, out, &prod)
	return ok
}

func (m *ModulusBasic) modDivEven(out, x, y *Nat) ct.Bool {
	// Grab big.Int views
	mBig := m.Big()
	xr := new(big.Int).Mod((*saferith.Nat)(x).Big(), mBig)
	yr := new(big.Int).Mod((*saferith.Nat)(y).Big(), mBig)

	// d = gcd(yr, m), and s,t with s*yr + t*m = d
	var s, t, d big.Int
	d.GCD(&s, &t, yr, mBig)

	// No solution unless d | xr
	if new(big.Int).Mod(xr, &d).Sign() != 0 {
		return ct.False
	}

	// Reduce by d
	xprime := new(big.Int).Quo(xr, &d)
	mprime := new(big.Int).Quo(mBig, &d)

	// From s*yr + t*m = d ⇒ s*(yr/d) ≡ 1 (mod m/d).
	// So s (mod m') is an inverse of y' = yr/d modulo m'.
	s.Mod(&s, mprime)
	if s.Sign() < 0 {
		s.Add(&s, mprime)
	}

	// u0 = x' * (y')^{-1} mod m'
	u0 := new(big.Int).Mod(new(big.Int).Mul(xprime, &s), mprime)

	// Encode back
	outNat := new(saferith.Nat).SetBig(u0, u0.BitLen())
	out.Set((*Nat)(outNat))
	return ct.True
}

// ModDiv sets out = x * y^{-1} (mod m).
func (m *ModulusBasic) ModDiv(out, x, y *Nat) ct.Bool {
	if m.Nat().IsOdd() == ct.True {
		return m.modDivOdd(out, x, y)
	} else {
		return m.modDivEven(out, x, y)
	}
}

func (m *ModulusBasic) modInvOdd(out, x *Nat) ct.Bool {
	(*saferith.Nat)(out).ModInverse(
		(*saferith.Nat)(x),
		(*saferith.Modulus)(m),
	)
	var shouldBeOne Nat
	m.ModMul(&shouldBeOne, out, x)
	return shouldBeOne.IsOne()
}

func (m *ModulusBasic) modInvEven(out, x *Nat) ct.Bool {
	ok := x.IsNonZero() & x.Coprime(m.Nat())
	if ok == ct.True {
		(*saferith.Nat)(out).SetBig(
			new(big.Int).ModInverse((*saferith.Nat)(x).Big(), (*saferith.Modulus)(m).Big()),
			(*saferith.Modulus)(m).BitLen(),
		)
	}
	return ok
}

// ModInv sets out = x^{-1} (mod m).
func (m *ModulusBasic) ModInv(out, x *Nat) ct.Bool {
	if m.Nat().IsOdd() == ct.True {
		return m.modInvOdd(out, x)
	} else {
		return m.modInvEven(out, x)
	}
}

// ModNeg sets out = -x (mod m).
func (m *ModulusBasic) ModNeg(out, x *Nat) {
	(*saferith.Nat)(out).ModNeg((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

func (m *ModulusBasic) modSqrtPrime(out, x *Nat) ct.Bool {
	// Reduce x modulo m to avoid mutating caller inputs and ensure range.
	xr := (*Nat)(new(saferith.Nat).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m)))

	root := (*Nat)(new(saferith.Nat).ModSqrt((*saferith.Nat)(xr), (*saferith.Modulus)(m)))

	var rootSquared Nat
	m.ModMul(&rootSquared, root, root)

	ok := rootSquared.Equal(xr)
	out.Select(ok, out, root)
	return ok
}

func (m *ModulusBasic) modSqrtGeneric(out, x *Nat) ct.Bool {
	reducedXBig := new(saferith.Nat).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m)).Big()
	res := new(big.Int).Sqrt(reducedXBig)
	squaredRes := new(big.Int).Mul(res, res)
	if squaredRes.Cmp(reducedXBig) != 0 {
		return ct.False
	}
	// Use the modulus bitlen for consistency
	bitlen := (*saferith.Modulus)(m).BitLen()
	out.Set((*Nat)(new(saferith.Nat).SetBig(res, bitlen)))
	return ct.True
}

// ModSqrt sets out = sqrt(x) (mod m) if it exists.
func (m *ModulusBasic) ModSqrt(out, x *Nat) ct.Bool {
	if m.Nat().IsProbablyPrime() == ct.True {
		return m.modSqrtPrime(out, x)
	} else {
		return m.modSqrtGeneric(out, x)
	}
}

func (m *ModulusBasic) modExpOdd(out, b, exp *Nat) {
	(*saferith.Nat)(out).Exp(
		(*saferith.Nat)(b),
		(*saferith.Nat)(exp),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusBasic) modExpEven(out, b *Nat, exp *big.Int) {
	baseBig := (*saferith.Nat)(b).Big()
	modBig := (*saferith.Modulus)(m).Big()

	result := new(big.Int).Exp(baseBig, exp, modBig)
	bitlen := (*saferith.Modulus)(m).BitLen()
	(*saferith.Nat)(out).SetBig(result, bitlen)
}

// ModExp sets out = base^exp (mod m).
func (m *ModulusBasic) ModExp(out, b, exp *Nat) {
	if m.Nat().IsOdd() == ct.True {
		m.modExpOdd(out, b, exp)
	} else {
		// For even moduli (like 2), we can't use Montgomery multiplication
		// Use big.Int instead
		m.modExpEven(out, b, exp.Big())
	}
}

func (m *ModulusBasic) modExpIOdd(out, b *Nat, exp *Int) {
	(*saferith.Nat)(out).ExpI(
		(*saferith.Nat)(b),
		(*saferith.Int)(exp),
		(*saferith.Modulus)(m),
	)
}

// ModExpI sets out = base^exp (mod m) where exp is an Int.
func (m *ModulusBasic) ModExpI(out, b *Nat, exp *Int) {
	if m.Nat().IsOdd() == ct.True {
		m.modExpIOdd(out, b, exp)
	} else {
		// For even moduli (like 2), we can't use Montgomery multiplication
		// Use big.Int instead
		m.modExpEven(out, b, exp.Big())
	}
}

// ModMultiBaseExp sets out[i] = bases[i]^exp (mod m) for all i.
func (m *ModulusBasic) ModMultiBaseExp(out, bases []*Nat, exp *Nat) {
	if len(bases) != len(out) {
		panic("len(bases) != len(out)")
	}
	var wg sync.WaitGroup
	wg.Add(len(bases))
	for i, bi := range bases {
		go func(i int) {
			defer wg.Done()
			m.ModExp(out[i], bi, exp)
		}(i)
	}
	wg.Wait()
}

// ModMul sets out = (x * y) (mod m).
func (m *ModulusBasic) ModMul(out, x, y *Nat) {
	(*saferith.Nat)(out).ModMul(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

// IsInRange returns true if 0 <= x < m.
func (m *ModulusBasic) IsInRange(x *Nat) ct.Bool {
	_, _, lt := (*saferith.Nat)(x).Cmp((*saferith.Modulus)(m).Nat())
	return ct.Bool(lt)
}

// IsInRangeSymmetric returns true if -m/2 <= x <= m/2.
func (m *ModulusBasic) IsInRangeSymmetric(x *Int) ct.Bool {
	mod := (*Nat)(((*saferith.Modulus)(m)).Nat()).Lift()
	var x2, modNeg Int
	modNeg.Neg(mod)
	x2.Add(x, x)
	ltn, _, _ := x2.Compare(&modNeg)
	ltp, _, _ := x2.Compare(mod)
	return ltn.Not() & ltp
}

// IsUnit returns true if x is a unit modulo m.
func (m *ModulusBasic) IsUnit(x *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(x).IsUnit((*saferith.Modulus)(m)))
}

// BitLen returns the bit length of the modulus.
func (m *ModulusBasic) BitLen() int {
	return (*saferith.Modulus)(m).BitLen()
}

// Nat returns the Nat representation of the modulus.
func (m *ModulusBasic) Nat() *Nat {
	return (*Nat)((*saferith.Modulus)(m).Nat())
}

// SetNat sets m = n where n is a Nat.
func (m *ModulusBasic) SetNat(n *Nat) ct.Bool {
	ok := n.IsNonZero()
	var nn Nat
	nn.Select(ok, NatOne(), n)
	m.Set((*ModulusBasic)(saferith.ModulusFromNat((*saferith.Nat)(&nn))))
	return ok
}

// Bytes returns the big-endian byte representation of the modulus.
func (m *ModulusBasic) Bytes() []byte {
	return (*saferith.Modulus)(m).Bytes()
}

// BytesBE returns the big-endian byte representation of the modulus.
func (m *ModulusBasic) BytesBE() []byte {
	return (*saferith.Modulus)(m).Bytes()
}

// String returns the string representation of the modulus.
func (m *ModulusBasic) String() string {
	return (*saferith.Modulus)(m).String()
}
