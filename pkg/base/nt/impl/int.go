package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/cronokirby/saferith"
)

var (
	SafeIntOne  = new(saferith.Int).SetUint64(1).Resize(1)
	SafeIntZero = new(saferith.Int).SetUint64(0).Resize(1)

	_ (internal.IntMutable[*Int]) = (*Int)(nil)
)

type Int saferith.Int

func (i *Int) Abs() {
	(*saferith.Int)(i).Neg(saferith.Choice(i.IsNegative()))
}

func (i *Int) abs() *Nat {
	return (*Nat)((*saferith.Int)(i).Abs())
}

func (i *Int) Set(v *Int) {
	*i = *v
}

func (i *Int) SetNat(v *Nat) {
	(*saferith.Int)(i).SetNat((*saferith.Nat)(v))
}

func (i *Int) Clone() *Int {
	return (*Int)((*saferith.Int)(i).Clone())
}

func (i *Int) SetZero() {
	i.Set((*Int)(SafeIntZero).Clone())
}

func (i *Int) SetOne() {
	i.Set((*Int)(SafeIntOne).Clone())
}

func (i *Int) Add(lhs, rhs *Int) {
	i.AddCap(lhs, rhs, -1)
}

func (i *Int) AddCap(lhs, rhs *Int, cap algebra.Capacity) {
	self := (*saferith.Int)(i)
	lhs_ := (*saferith.Int)(lhs)
	rhs_ := (*saferith.Int)(rhs)
	self.Add(lhs_, rhs_, cap)
}

func (i *Int) Neg(x *Int) {
	i.Set(x)
	(*saferith.Int)(i).Neg(saferith.Choice(1))
}

func (i *Int) Sub(lhs, rhs *Int) {
	i.SubCap(lhs, rhs, -1)
}

func (i *Int) SubCap(lhs, rhs *Int, cap algebra.Capacity) {
	self := (*saferith.Int)(i)
	lhs_ := (*saferith.Int)(lhs)

	// Create a copy of rhs and negate it
	var negRhs saferith.Int
	negRhs.SetNat((*saferith.Nat)(rhs.abs()))
	negRhs.Neg(saferith.Choice(rhs.IsNegative() ^ 1))

	self.Add(lhs_, &negRhs, cap)
}

func (i *Int) Mul(lhs, rhs *Int) {
	i.MulCap(lhs, rhs, -1)
}

func (i *Int) MulCap(lhs, rhs *Int, cap algebra.Capacity) {
	self := (*saferith.Int)(i)
	lhs_ := (*saferith.Int)(lhs)
	rhs_ := (*saferith.Int)(rhs)
	self.Mul(lhs_, rhs_, cap)
}

func (i *Int) Mod(a, m *Int) (ok ct.Bool) {
	absNat := new(Nat)
	ok = absNat.Mod(a.abs(), m.abs())
	res := new(Int)
	res.SetNat(absNat)
	(*saferith.Int)(res).Neg(saferith.Choice(a.IsNegative() ^ m.IsNegative()))
	i.Select(ok, i, res)
	return ok
}

func (i *Int) Div(lhs, rhs *Int) (ok ct.Bool) {
	return i.DivCap(lhs, rhs, -1)
}

func (i *Int) DivCap(lhs, rhs *Int, cap algebra.Capacity) (ok ct.Bool) {
	absRes := new(Nat)
	ok = absRes.DivCap(lhs.abs(), rhs.abs(), cap)

	// Create the result value
	result := new(Int)
	result.SetNat(absRes)
	(*saferith.Int)(result).Neg(saferith.Choice(lhs.IsNegative() ^ rhs.IsNegative()))

	// Only update i if division was exact
	i.Select(ct.Choice(ok), i, result)
	return ok
}

// DivModCap computes lhs / rhs and lhs % rhs, storing the results into outQuot and outRem.
// The cap parameter sets the announced capacity (in bits) for the quotient.
// Signs follow Go's integer division/modulo semantics:
//   - Quotient sign: negative if exactly one of lhs or rhs is negative.
//   - Remainder sign: same as lhs.
//
// If rhs.abs() == 0, behaviour is undefined and may panic inside saferith.
func (i *Int) DivModCap(outQuot, outRem, a, b *Int, cap algebra.Capacity) (ok ct.Bool) {
	outQuotNat := new(Nat)
	outRemNat := new(Nat)

	dummy := new(Nat)
	ok = dummy.DivModCap(outQuotNat, outRemNat, a.abs(), b.abs(), cap)

	// Set the absolute values
	outQuot.SetNat(outQuotNat)
	outRem.SetNat(outRemNat)

	// Apply signs: quotient is negative if signs differ, remainder has same sign as dividend
	quotShouldNegate := saferith.Choice(a.IsNegative() ^ b.IsNegative())
	remShouldNegate := saferith.Choice(a.IsNegative())

	(*saferith.Int)(outQuot).Neg(quotShouldNegate)
	(*saferith.Int)(outRem).Neg(remShouldNegate)

	return ok
}

func (i *Int) Inv(x *Int) (ok ct.Bool) {
	return ct.False
}

func (i *Int) Double(x *Int) {
	i.Add(x, x)
}

func (i *Int) IsNegative() ct.Bool {
	return ct.Bool((*saferith.Int)(i).IsNegative())
}

func (i *Int) IsZero() ct.Bool {
	return i.abs().IsZero()
}

func (i *Int) IsNonZero() ct.Bool {
	return i.IsZero().Not()
}

func (i *Int) IsOne() ct.Bool {
	return i.Equal((*Int)(SafeIntOne))
}

func (i *Int) Sqrt(x *Int) (ok ct.Bool) {
	// Constant-time (w.r.t. announced capacity) integer square root.
	// Work on |x| and assign only if |x| is a perfect square.

	// Negative numbers are never perfect squares in Z.
	nonNeg := x.IsNegative().Not()

	// Magnitude and (public) capacity.
	a := x.abs()
	capBits := int(a.AnnouncedLen())

	var rootNat saferith.Nat
	var okRes ct.Bool

	// ===== Single-limb fast path (<= 64 bits): 32 fixed rounds, branchless. =====
	if capBits <= 64 {
		u0 := a.Uint64()
		r64 := ct.Isqrt64(u0)
		rootNat.SetUint64(r64).Resize(capBits)

		// Exactness check: r64^2 fits in uint64 because r64 <= 2^32.
		sq := r64 * r64
		okRes = ct.Bool(ct.Equal(sq, u0))
	} else {
		// ===== Multi-limb path: restoring (digit-by-digit) method. =====
		// Runtime depends only on capBits (pairs), not on the value.
		var n saferith.Nat // remainder
		n.SetNat((*saferith.Nat)(a))
		n.Resize(capBits)

		var y saferith.Nat // accumulating root
		y.SetUint64(0)
		y.Resize(capBits)

		pairs := (capBits + 1) / 2 // number of two-bit groups to process

		// b := 1 << startEven, where startEven is the top even bit < capBits
		var b saferith.Nat
		b.SetUint64(1)
		if pairs > 0 {
			startEven := 2 * (pairs - 1)
			b.Lsh(&b, uint(startEven), algebra.Capacity(capBits))
		} else {
			b.Resize(capBits)
		}

		// Scratch (BoringSSL-style reuse).
		var m saferith.Nat      // y + b
		var yshr saferith.Nat   // y >> 1
		var nMinus saferith.Nat // n - m
		var yPlus saferith.Nat  // (y>>1) + b
		var bshr saferith.Nat   // b >> 2

		for range pairs {
			// m = y + b
			m.Add(&y, &b, algebra.Capacity(capBits))

			// yshr = y >> 1 (computed unconditionally)
			yshr.Rsh(&y, 1, algebra.Capacity(capBits))

			// Candidates (computed unconditionally)
			nMinus.Sub(&n, &m, algebra.Capacity(capBits))   // n - m
			yPlus.Add(&yshr, &b, algebra.Capacity(capBits)) // (y>>1) + b

			// ge := (n >= m) in constant time.
			gt, eq, _ := n.Cmp(&m)
			ge := gt | eq

			// Apply updates branchlessly.
			n.Select(ge, &nMinus)
			y = yshr
			y.Select(ge, &yPlus)

			// b >>= 2
			bshr.Rsh(&b, 2, algebra.Capacity(capBits))
			b = bshr
		}

		// ok iff remainder is zero.
		var z saferith.Nat
		z.Resize(capBits)
		_, eqZero, _ := n.Cmp(&z)
		okRes = ct.Bool(eqZero)

		rootNat.SetNat(&y)
	}

	ok = okRes & nonNeg

	// Conditionally assign the root.
	var root Int
	(*saferith.Int)(&root).SetNat(&rootNat)
	i.Select(ok, i, &root)
	return
}

func (i *Int) Square(x *Int) {
	i.Mul(x, x)
}

func (i *Int) Bit(index uint) byte {
	return i.abs().Bit(index)
}

func (i *Int) Bytes() []byte {
	return i.abs().Bytes()
}

func (i *Int) SetBytes(b []byte) (ok ct.Bool) {
	(*saferith.Int)(i).SetBytes(b)
	return ct.True
}

func (i *Int) Increment() {
	i.Add(i, (*Int)(SafeIntOne))
}

func (i *Int) Decrement() {
	i.Sub(i, (*Int)(SafeIntOne))
}

func (i *Int) Lsh(x *Int, shift uint) {
	i.LshCap(x, shift, -1)
}

func (i *Int) LshCap(x *Int, shift uint, cap algebra.Capacity) {
	out := i.abs()
	out.LshCap(x.abs(), shift, cap)
	i.SetNat(out)
	// Preserve sign
	(*saferith.Int)(i).Neg(saferith.Choice(x.IsNegative()))
}

func (i *Int) Rsh(x *Int, shift uint) {
	i.RshCap(x, shift, -1)
}

func (i *Int) RshCap(x *Int, shift uint, cap algebra.Capacity) {
	out := i.abs()
	out.RshCap(x.abs(), shift, cap)
	i.SetNat(out)
	// Preserve sign
	(*saferith.Int)(i).Neg(saferith.Choice(x.IsNegative()))
}

func (i *Int) Resize(cap algebra.Capacity) {
	(*saferith.Int)(i).Resize(cap)
}

func (i *Int) Coprime(rhs *Int) ct.Bool {
	return i.abs().Coprime(rhs.abs())
}

func (i *Int) IsProbablyPrime() ct.Bool {
	return i.abs().IsProbablyPrime() & i.IsNegative().Not()
}

func (i *Int) Select(choice ct.Choice, x0, x1 *Int) {
	// Select should set i = choice ? x1 : x0
	// Since saferith.Int doesn't have Select, we need to implement it ourselves

	// Get absolute values
	abs0 := x0.abs()
	abs1 := x1.abs()

	// Use Nat's Select for the magnitude
	var selectedAbs Nat
	selectedAbs.Set(abs0)
	selectedAbs.Select(choice, &selectedAbs, abs1)

	// Select the sign
	selectedNeg := ct.SelectInteger(choice, x0.IsNegative(), x1.IsNegative())

	// Set the result
	i.SetNat(&selectedAbs)
	(*saferith.Int)(i).Neg(saferith.Choice(selectedNeg))
}

func (i *Int) Equal(rhs *Int) ct.Bool {
	return ct.Bool((*saferith.Int)(i).Eq((*saferith.Int)(rhs)))
}

func (i *Int) Compare(rhs *Int) (lt, eq, gt ct.Bool) {
	// Signs as ct.Bool (0/1)
	aNeg := i.IsNegative()
	bNeg := rhs.IsNegative()

	// Magnitude compare on |i| and |rhs|
	ltM, eqM, gtM := i.abs().Compare(rhs.abs())

	// same = 1 iff signs are equal
	same := (aNeg ^ bNeg).Not()
	// bothNeg = 1 iff both are negative
	bothNeg := same & aNeg

	// If both negative, reverse magnitude ordering
	ltSame := ct.SelectInteger(bothNeg, ltM, gtM) // when bothNeg==0 pick ltM, when bothNeg==1 pick gtM
	gtSame := ct.SelectInteger(bothNeg, gtM, ltM) // when bothNeg==0 pick gtM, when bothNeg==1 pick ltM

	// Only use magnitude comparison when signs are the same
	ltSame = same & ltSame
	gtSame = same & gtSame
	eqSame := same & eqM

	// Different signs: negative < non-negative
	ltDiff := aNeg & (bNeg ^ 1) // a neg, b non-neg
	gtDiff := (aNeg ^ 1) & bNeg // a non-neg, b neg

	lt = ltSame | ltDiff
	gt = gtSame | gtDiff
	eq = eqSame
	return
}

func (i *Int) Uint64() uint64 {
	return i.abs().Uint64()
}

func (i *Int) SetUint64(x uint64) {
	(*saferith.Int)(i).SetUint64(x)
}

func (i *Int) Int64() int64 {
	abs := int64(i.abs().Uint64())
	negated := abs * -1
	// When IsNegative() is 1 (true), select negated
	// ct.Select returns x1 when choice is 1, x0 when choice is 0
	return ct.SelectInteger(i.IsNegative(), abs, negated)
}

func (i *Int) SetInt64(x int64) {
	ux := uint64(x)

	// s is all 1s (0xFFFF..FFFF) if x < 0, else 0.
	s := uint64(int64(x) >> 63)

	// mag = |x| as uint64, computed without branches and safe for MinInt64.
	// For x >= 0: (ux ^ 0) - 0 = ux
	// For x < 0 : (ux ^ s) - s = (~ux) + 1  == two's-complement abs(x)
	mag := (ux ^ s) - s

	// Set magnitude, then apply sign in constant time.
	(*saferith.Int)(i).SetUint64(mag)

	// Negate iff x < 0. (ux>>63) is 1 for negative x, 0 otherwise.
	(*saferith.Int)(i).Neg(saferith.Choice((ux >> 63) & 1))
}

func (i *Int) TrueLen() uint {
	return uint((*saferith.Int)(i).TrueLen())
}

func (i *Int) AnnouncedLen() uint {
	return uint((*saferith.Int)(i).AnnouncedLen())
}

func (i *Int) IsOdd() ct.Bool {
	return i.abs().IsOdd()
}

func (i *Int) IsEven() ct.Bool {
	return i.IsOdd().Not()
}

func (i *Int) String() string {
	return (*saferith.Int)(i).String()
}
