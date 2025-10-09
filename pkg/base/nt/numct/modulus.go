package numct

import (
	"io"
	"math/big"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/cronokirby/saferith"
)

type Modulus internal.ModulusMutable[*Int, *Nat, Modulus]

var (
	_ (Modulus) = (*ModulusOddPrimeBasic)(nil)
	_ (Modulus) = (*ModulusOddBasic)(nil)
	_ (Modulus) = (*ModulusBasic)(nil)
)

func NewModulus(m *Nat) (Modulus, ct.Bool) {
	mIsPrime := m.IsProbablyPrime()
	mIsOdd := m.IsOdd()
	mIsNonZero := m.IsNonZero()

	switch {
	case mIsPrime&mIsOdd&mIsNonZero == ct.True:
		return NewModulusOddPrime(m)
	case mIsOdd&mIsNonZero == ct.True:
		return NewModulusOdd(m)
	case mIsNonZero == ct.True:
		return NewModulusNonZero(m)
	default:
		return nil, ct.False
	}
}

func newModulusOddPrimeBasic(m *Nat) *ModulusOddPrimeBasic {
	return (*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(m)))
}

func newModulusOddBasic(m *Nat) *ModulusOddBasic {
	return &ModulusOddBasic{
		ModulusOddPrimeBasic: *newModulusOddPrimeBasic(m),
	}
}

func newModulusBasic(m *Nat) *ModulusBasic {
	return &ModulusBasic{
		ModulusOddBasic: *newModulusOddBasic(m),
	}
}

type (
	ModulusOddPrimeBasic saferith.Modulus
	ModulusOddBasic      struct {
		ModulusOddPrimeBasic
	}
	ModulusBasic struct {
		ModulusOddBasic
	}
)

func (m *ModulusOddPrimeBasic) HashCode() base.HashCode {
	return base.DeriveHashCode(m.Bytes())
}

func (m *ModulusOddPrimeBasic) Random(prng io.Reader) (*Nat, error) {
	return NatRandomRangeH(prng, m.Nat())
}

func (m *ModulusOddPrimeBasic) Big() *big.Int {
	return (*saferith.Modulus)(m).Big()
}

func (m *ModulusOddPrimeBasic) Saferith() *saferith.Modulus {
	return (*saferith.Modulus)(m)
}

func (m *ModulusOddPrimeBasic) Set(v *ModulusOddPrimeBasic) {
	*m = *v
}

func (m *ModulusOddPrimeBasic) Mod(out, x *Nat) {
	(*saferith.Nat)(out).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

func (m *ModulusOddPrimeBasic) ModInt(out *Nat, x *Int) {
	out = (*Nat)((*saferith.Int)(x).Mod((*saferith.Modulus)(m)))
}

func (m *ModulusOddPrimeBasic) ModSymmetric(out *Int, x *Nat) {
	(*saferith.Int)(out).SetModSymmetric((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

func (m *ModulusOddPrimeBasic) Quo(out, x *Nat) {
	(*saferith.Nat)(out).Div(
		(*saferith.Nat)(x),
		(*saferith.Modulus)(m),
		int(m.BitLen()),
	)
}

func (m *ModulusOddPrimeBasic) ModAdd(out, x, y *Nat) {
	(*saferith.Nat)(out).ModAdd(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrimeBasic) ModSub(out, x, y *Nat) {
	(*saferith.Nat)(out).ModSub(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

// ModDiv sets out = x * y^{-1} (mod m) without using exponentiation.
func (m *ModulusOddPrimeBasic) ModDiv(out, x, y *Nat) ct.Bool {
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

func (m *ModulusOddPrimeBasic) ModInv(out, x *Nat) ct.Bool {
	(*saferith.Nat)(out).ModInverse(
		(*saferith.Nat)(x),
		(*saferith.Modulus)(m),
	)
	return m.Nat().IsOdd() & x.Coprime(m.Nat())
}

func (m *ModulusOddPrimeBasic) ModNeg(out, x *Nat) {
	(*saferith.Nat)(out).ModNeg((*saferith.Nat)(x), (*saferith.Modulus)(m))
}

func (m *ModulusOddPrimeBasic) ModSqrt(out, x *Nat) ct.Bool {
	// Reduce x modulo m to avoid mutating caller inputs and ensure range.
	xr := (*Nat)(new(saferith.Nat).Mod((*saferith.Nat)(x), (*saferith.Modulus)(m)))

	root := (*Nat)(new(saferith.Nat).ModSqrt((*saferith.Nat)(xr), (*saferith.Modulus)(m)))

	var rootSquared Nat
	m.ModMul(&rootSquared, root, root)

	ok := rootSquared.Equal(xr)
	out.Select(ok, out, root)
	return ok
}

func (m *ModulusOddPrimeBasic) ModExp(out, base, exp *Nat) {
	(*saferith.Nat)(out).Exp(
		(*saferith.Nat)(base),
		(*saferith.Nat)(exp),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrimeBasic) ModExpInt(out, base *Nat, exp *Int) {
	(*saferith.Nat)(out).ExpI(
		(*saferith.Nat)(base),
		(*saferith.Int)(exp),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrimeBasic) ModMultiBaseExp(out []*Nat, bases []*Nat, exp *Nat) {
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

func (m *ModulusOddPrimeBasic) ModMul(out, x, y *Nat) {
	(*saferith.Nat)(out).ModMul(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrimeBasic) IsInRange(x *Nat) ct.Bool {
	// x is in range if 0 <= x < m
	// Cmp returns (>, =, <) in that order
	_, _, lt := (*saferith.Nat)(x).Cmp((*saferith.Modulus)(m).Nat())
	return ct.Bool(lt)
}

func (m *ModulusOddPrimeBasic) IsInRangeSymmetric(x *Int) ct.Bool {
	return ct.Bool((*saferith.Int)(x).CheckInRange((*saferith.Modulus)(m)))
}

func (m *ModulusOddPrimeBasic) IsUnit(x *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(x).IsUnit((*saferith.Modulus)(m)))
}

func (m *ModulusOddPrimeBasic) BitLen() uint {
	return uint((*saferith.Modulus)(m).BitLen())
}

func (m *ModulusOddPrimeBasic) Nat() *Nat {
	return (*Nat)((*saferith.Modulus)(m).Nat())
}

func (m *ModulusOddPrimeBasic) SetNat(n *Nat) ct.Bool {
	ok := n.IsNonZero() & n.IsOdd() & n.IsProbablyPrime()
	var nn Nat
	nn.Select(ok, NatThree(), n)
	m.Set((*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(&nn))))
	return n.IsNonZero()
}

func (m *ModulusOddPrimeBasic) Bytes() []byte {
	return (*saferith.Modulus)(m).Bytes()
}

func (m *ModulusOddPrimeBasic) String() string {
	return (*saferith.Modulus)(m).String()
}

// ********* Odd Composite Modulus ************

func (m *ModulusOddBasic) Set(v *ModulusOddBasic) {
	*m = *v
}

func (m *ModulusOddBasic) SetNat(n *Nat) ct.Bool {
	ok := n.IsNonZero() & n.IsOdd()
	var nn Nat
	nn.Select(ok, NatThree(), n)
	*m = ModulusOddBasic{
		ModulusOddPrimeBasic: *(*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(&nn))),
	}
	return ok
}

func (m *ModulusOddBasic) ModSqrt(out, x *Nat) ct.Bool {
	reducedXBig := new(saferith.Nat).Mod((*saferith.Nat)(x), (*saferith.Modulus)(&m.ModulusOddPrimeBasic)).Big()
	res := new(big.Int).Sqrt(reducedXBig)
	squaredRes := new(big.Int).Mul(res, res)
	if squaredRes.Cmp(reducedXBig) != 0 {
		return ct.False
	}
	// Use the modulus bitlen for consistency
	bitlen := (*saferith.Modulus)(&m.ModulusOddPrimeBasic).BitLen()
	out.Set((*Nat)(new(saferith.Nat).SetBig(res, bitlen)))
	return ct.True
}

// ********* Generic Modulus *****************

// ModDiv solves y * u ≡ x (mod m) and writes one solution u into out.
// Works for even/composite moduli. Variable-time (uses big.Int.GCD).
// Returns ok=false iff no solution (i.e., gcd(y,m) ∤ x).
func (m *ModulusBasic) ModDiv(out, x, y *Nat) ct.Bool {
	// Grab big.Int views
	mBig := (*saferith.Modulus)(&m.ModulusOddBasic.ModulusOddPrimeBasic).Big()
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

func (m *ModulusBasic) ModInv(out, x *Nat) ct.Bool {
	ok := x.IsNonZero() & x.Coprime(m.Nat())
	if ok == ct.True {
		(*saferith.Nat)(out).SetBig(
			new(big.Int).ModInverse((*saferith.Nat)(x).Big(), (*saferith.Modulus)(&m.ModulusOddPrimeBasic).Big()),
			(*saferith.Modulus)(&m.ModulusOddPrimeBasic).BitLen(),
		)
	}
	return ok
}

func (m *ModulusBasic) Set(v *ModulusBasic) {
	*m = *v
}

func (m *ModulusBasic) SetNat(n *Nat) ct.Bool {
	ok := n.IsNonZero()
	var nn Nat
	nn.Select(ok, NatThree(), n)
	*m = ModulusBasic{
		ModulusOddBasic: ModulusOddBasic{
			ModulusOddPrimeBasic: *(*ModulusOddPrimeBasic)(saferith.ModulusFromNat((*saferith.Nat)(&nn))),
		},
	}
	return ok
}

func (m *ModulusBasic) ModExp(out, base, exp *Nat) {
	// For even moduli (like 2), we can't use Montgomery multiplication
	// Use big.Int instead
	baseBig := (*saferith.Nat)(base).Big()
	expBig := (*saferith.Nat)(exp).Big()
	modBig := (*saferith.Modulus)(&m.ModulusOddPrimeBasic).Big()

	result := new(big.Int).Exp(baseBig, expBig, modBig)
	bitlen := (*saferith.Modulus)(&m.ModulusOddPrimeBasic).BitLen()
	(*saferith.Nat)(out).SetBig(result, bitlen)
}
