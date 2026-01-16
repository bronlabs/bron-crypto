package numct

import (
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// IntOne returns a new Int set to 1.
func IntOne() *Int {
	return (*Int)(new(saferith.Int).SetUint64(1).Resize(1))
}

// IntZero returns a new Int set to 0.
func IntZero() *Int {
	return (*Int)(new(saferith.Int).SetUint64(0).Resize(1))
}

// NewInt creates a new Int set to the given int64 value.
func NewInt(value int64) *Int {
	n := new(Int)
	n.SetInt64(value)
	return n
}

// NewIntFromUint64 creates a new Int set to the given uint64 value.
func NewIntFromUint64(value uint64) *Int {
	n := new(Int)
	n.SetUint64(value)
	return n
}

// NewIntFromSaferith creates a new Int from a saferith.Int.
func NewIntFromSaferith(n *saferith.Int) *Int {
	return (*Int)(n)
}

// NewIntFromBytes creates a new Int from a big-endian byte slice.
func NewIntFromBytes(b []byte) *Int {
	n := new(Int)
	n.SetBytes(b)
	return n
}

// NewIntFromBig creates a new Int from a big.Int with the given capacity.
func NewIntFromBig(n *big.Int, capacity int) *Int {
	return (*Int)(new(saferith.Int).SetBig(n, capacity))
}

type Int saferith.Int

// Abs sets i = |i|.
func (i *Int) Abs(x *Int) {
	i.Set(x)
	(*saferith.Int)(i).Neg(saferith.Choice(i.IsNegative()))
}

// Set sets i = v.
func (i *Int) Set(v *Int) {
	(*saferith.Int)(i).SetInt((*saferith.Int)(v))
}

// SetNat sets i = v where v is a Nat.
func (i *Int) SetNat(v *Nat) {
	i.Set((*Int)(new(saferith.Int).SetNat((*saferith.Nat)(v))))
}

// Clone returns a copy of i.
func (i *Int) Clone() *Int {
	return (*Int)((*saferith.Int)(i).Clone())
}

// SetZero sets i = 0.
func (i *Int) SetZero() {
	i.Set(IntZero())
}

// SetOne sets i = 1.
func (i *Int) SetOne() {
	i.Set(IntOne())
}

// Add sets i = lhs + rhs.
func (i *Int) Add(lhs, rhs *Int) {
	i.AddCap(lhs, rhs, -1)
}

// AddCap sets i = lhs + rhs with capacity capacity.
// When capacity < 0, it is set to max(lhs.AnnouncedLen(), rhs.AnnouncedLen()) + 1.
func (i *Int) AddCap(lhs, rhs *Int, capacity int) {
	(*saferith.Int)(i).Add((*saferith.Int)(lhs), (*saferith.Int)(rhs), capacity)
}

// Neg sets i = -x.
func (i *Int) Neg(x *Int) {
	i.Set((*Int)((*saferith.Int)(x.Clone()).Neg(saferith.Choice(1))))
}

// Sub sets i = lhs - rhs.
func (i *Int) Sub(lhs, rhs *Int) {
	i.SubCap(lhs, rhs, -1)
}

// SubCap sets i = lhs - rhs with capacity capacity.
// When capacity < 0, it is set to max(lhs.AnnouncedLen(), rhs.AnnouncedLen()) + 1.
func (i *Int) SubCap(lhs, rhs *Int, capacity int) {
	rhsNeg := rhs.Clone()
	rhsNeg.Neg(rhs)
	i.AddCap(lhs, rhsNeg, capacity)
}

// Mul sets i = lhs * rhs.
func (i *Int) Mul(lhs, rhs *Int) {
	i.MulCap(lhs, rhs, -1)
}

// MulCap sets i = lhs * rhs with capacity capacity.
// When capacity < 0, it is set to lhs.AnnouncedLen() + rhs.AnnouncedLen().
func (i *Int) MulCap(lhs, rhs *Int, capacity int) {
	(*saferith.Int)(i).Mul((*saferith.Int)(lhs), (*saferith.Int)(rhs), capacity)
}

// EuclideanDiv sets n to quotient of numerator / denominator.
// If r is not nil, it will be set it to the remainder.
// It returns ok=1 if the division was successful, ok=0 otherwise (i.e., division by zero).
// The number of bits of the quotient will be numerator.AnnouncedLen() and
// the number of bits of the remainder will be denominator.AnnouncedLen().
func (i *Int) EuclideanDiv(remainder *Nat, numerator, denominator *Int) (ok ct.Bool) {
	var qq, rr, n, d Nat
	n.Abs(numerator)
	d.Abs(denominator)
	ok = qq.EuclideanDiv(&rr, &n, &d)
	sa := numerator.IsNegative()
	sb := denominator.IsNegative()
	z := rr.IsZero()

	var rOut, notR Int
	notR.Set(denominator)
	notR.CondNeg(notR.IsNegative())
	notR.Sub(&notR, rr.Lift())
	rOut.CondAssign(sa.Not(), rr.Lift())
	rOut.CondAssign(sa&z, IntZero())
	rOut.CondAssign(sa&(z^1), &notR)

	var qn, qn1, qa, qan, qOut Int
	qn.Neg(qq.Lift())
	qn1.Sub(&qn, IntOne())
	qa.CondAssign(sa.Not(), qq.Lift())
	qa.CondAssign(sa&z, &qn)
	qa.CondAssign(sa&z.Not(), &qn1)
	qan.Neg(&qa)
	qOut.CondAssign(sb, &qan)
	qOut.CondAssign(sb.Not(), &qa)
	qOut.Resize(numerator.AnnouncedLen())
	i.CondAssign(ok, &qOut)

	if remainder != nil {
		var rOutAbs Nat
		rOutAbs.Abs(&rOut)
		rOutAbs.Resize(denominator.AnnouncedLen())
		remainder.CondAssign(ok, &rOutAbs)
	}

	return ok
}

// EuclideanDivVarTime sets n to quotient of numerator / denominator.
// If r is not nil, it will be set it to the remainder.
// It returns ok=1 if the division was successful, ok=0 otherwise (i.e., division by zero).
// The number of bits of the quotient will be
// min(numerator.AnnouncedLen(), numerator.AnnouncedLen() - denominator.TrueLen() + 2) and
// the number of bits of the remainder will be denominator.AnnouncedLen().
func (i *Int) EuclideanDivVarTime(remainder *Nat, numerator, denominator *Int) (ok ct.Bool) {
	var qq, rr, n, d Nat
	n.Abs(numerator)
	d.Abs(denominator)
	ok = qq.EuclideanDivVarTime(&rr, &n, &d)
	if ok == ct.False {
		return ct.False
	}

	sa := numerator.IsNegative()
	sb := denominator.IsNegative()
	z := rr.IsZero()

	var qa Int
	if sa == ct.False {
		qa.Set(qq.Lift())
	} else if (sa & z) != ct.False {
		var qn Int
		qn.Neg(qq.Lift())
		qa.Set(&qn)
	} else {
		var qn, qn1 Int
		qn.Neg(qq.Lift())
		qn1.Sub(&qn, IntOne())
		qa.Set(&qn1)
	}

	var qOut Int
	if sb == ct.False {
		qOut.Set(&qa)
	} else {
		var qan Int
		qan.Neg(&qa)
		qOut.Set(&qan)
	}
	i.Set(&qOut)
	i.Resize(min(numerator.AnnouncedLen(), numerator.AnnouncedLen()-denominator.TrueLen()+2))

	if remainder != nil {
		var rOut Int
		if sa == ct.False {
			rOut.Set(rr.Lift())
		} else if (sa & z) != ct.False {
			rOut.Set(IntZero())
		} else {
			var notR Int
			notR.SetNat(&d)
			notR.Sub(&notR, rr.Lift())
			rOut.Set(&notR)
		}
		remainder.Abs(&rOut)
		remainder.Resize(denominator.TrueLen())
	}

	return ct.True
}

// Div sets n = numerator / denominator.
// If r is not nil, it will be set it to the remainder.
// It returns ok=1 if the division was successful, ok=0 otherwise (i.e., division by zero).
// The number of bits of the quotient will be numerator.AnnouncedLen() and
// the number of bits of the remainder will be denominator.AnnouncedLen().
func (i *Int) Div(remainder, numerator, denominator *Int) ct.Bool {
	ok := denominator.IsNonZero()
	ns := ((*saferith.Int)(numerator)).IsNegative()
	ds := ((*saferith.Int)(denominator)).IsNegative()
	qs := ns ^ ds
	rs := ns

	var q, r saferith.Nat
	nAbs := ((*saferith.Int)(numerator)).Abs()
	dAbs := ((*saferith.Int)(denominator)).Abs()
	_, _ = internal.EuclideanDiv(&q, &r, nAbs, dAbs)
	var qInt saferith.Int
	qInt.SetNat(&q)
	qInt.Neg(qs)
	qInt.Resize(numerator.AnnouncedLen())
	i.CondAssign(ok, (*Int)(&qInt))

	if remainder != nil {
		var rInt saferith.Int
		rInt.SetNat(&r)
		rInt.Neg(rs)
		rInt.Resize(denominator.AnnouncedLen())
		remainder.CondAssign(ok, (*Int)(&rInt))
	}

	return ok
}

// DivVarTime sets n to quotient of numerator / denominator.
// If r is not nil, it will be set it to the remainder.
// It returns ok=1 if the division was successful, ok=0 otherwise (i.e., division by zero).
// The number of bits of the quotient will be
// min(numerator.AnnouncedLen(), numerator.AnnouncedLen() - denominator.TrueLen() + 2) and
// the number of bits of the remainder will be denominator.AnnouncedLen().
func (i *Int) DivVarTime(remainder, numerator, denominator *Int) (ok ct.Bool) {
	if denominator.IsNonZero() == ct.False {
		return ct.False
	}

	ns := ((*saferith.Int)(numerator)).IsNegative()
	ds := ((*saferith.Int)(denominator)).IsNegative()
	qs := ns ^ ds
	rs := ns

	var q, r saferith.Nat
	nAbs := ((*saferith.Int)(numerator)).Abs()
	dAbs := ((*saferith.Int)(denominator)).Abs()
	_ = ((*Nat)(&q)).EuclideanDivVarTime((*Nat)(&r), (*Nat)(nAbs), (*Nat)(dAbs))
	var qInt saferith.Int
	qInt.SetNat(&q)
	qInt.Neg(qs)
	qInt.Resize(min(numerator.AnnouncedLen(), numerator.AnnouncedLen()-denominator.TrueLen()+2))
	i.Set((*Int)(&qInt))

	if remainder != nil {
		var rInt saferith.Int
		rInt.SetNat(&r)
		rInt.Neg(rs)
		rInt.Resize(denominator.TrueLen())
		remainder.Set((*Int)(&rInt))
	}

	return ct.True
}

// IsUnit returns true if i is a unit (i.e., ±1).
func (i *Int) IsUnit() ct.Bool {
	var n Nat
	n.Abs(i)
	return n.IsOne()
}

// Inv sets i = x^{-1}. It returns ok = false if x is not a unit.
func (i *Int) Inv(x *Int) (ok ct.Bool) {
	ok = x.IsUnit()
	i.CondAssign(ok, x)
	return ok
}

// GCD sets i = gcd(a, b) in Z, always non-negative.
// It is implemented via the constant-time Nat.GCD on |a| and |b|.
func (i *Int) GCD(a, b *Int) {
	if a == nil || b == nil {
		panic("numct.Int.GCD: nil input")
	}

	// Work with absolute values; gcd in Z is always taken as non-negative.
	var an, bn Nat
	an.Abs(a)
	bn.Abs(b)

	var g Nat
	g.GCD(&an, &bn)
	i.SetNat(&g)
}

// Double sets i = 2 * x.
func (i *Int) Double(x *Int) {
	i.Add(x, x)
}

// IsNegative returns 1 if i is negative.
func (i *Int) IsNegative() ct.Bool {
	return ct.Bool((*saferith.Int)(i).IsNegative())
}

// IsZero returns 1 if i == 0.
func (i *Int) IsZero() ct.Bool {
	var n Nat
	n.Abs(i)
	return n.IsZero()
}

// IsNonZero returns 1 if i != 0.
func (i *Int) IsNonZero() ct.Bool {
	return i.IsZero().Not()
}

// IsOne returns 1 if i == 1.
func (i *Int) IsOne() ct.Bool {
	return i.Equal(IntOne())
}

// Sqrt sets i = sqrt(x) if x is a perfect square, else leaves i unchanged.
// Returns ok = 1 if x is a perfect square.
func (i *Int) Sqrt(x *Int) (ok ct.Bool) {
	// Constant-time (w.r.t. announced capacity) integer square root.
	// Work on |x| and assign only if |x| is a perfect square.

	var inNat, outNat Nat
	inNat.Abs(x)
	ok = outNat.Sqrt(&inNat)

	// Negative numbers are never perfect squares in Z.
	ok &= x.IsNegative().Not()

	var out Int
	out.SetNat(&outNat)

	i.CondAssign(ok, &out)

	return ok
}

// Square sets i = x^2.
func (i *Int) Square(x *Int) {
	i.Mul(x, x)
}

//// Bit returns the value of the bit at the given index.
// func (i *Int) Bit(index uint) byte {
//	return i.Absed().Bit(index)
//}.

// Bytes returns a sign-magnitude encoding:
//
//	b[0] = 0 if i >= 0, 1 if i < 0
//	b[1:] = big-endian |i|
func (i *Int) Bytes() []byte {
	return errs2.Must1((*saferith.Int)(i).MarshalBinary())
}

// SetBytes expects the sign-magnitude encoding produced by Bytes/BytesBE:
//
//	b[0] = 0 for >=0, 1 for <0
//	b[1:] = big-endian |i|
//
// Returns ok = 0 only for obviously malformed input (empty slice).
func (i *Int) SetBytes(b []byte) (ok ct.Bool) {
	err := (*saferith.Int)(i).UnmarshalBinary(b)
	return utils.BoolTo[ct.Bool](err == nil)
}

// SetTwosComplementBEBytes sets i from the two's-complement big-endian byte representation.
func (i *Int) SetTwosComplementBEBytes(b []byte) {
	sign := b[0] >> 7
	notBytes := make([]byte, len(b))
	ct.NotBytes(notBytes, b)
	natBytes := make([]byte, len(b))
	subtle.ConstantTimeCopy(int(sign), natBytes, notBytes)
	subtle.ConstantTimeCopy(int(sign^0b1), natBytes, b)
	var nat saferith.Nat
	// Use len(b)*8 capacity to handle edge case where magnitude needs full width
	// (e.g., min int64 = -2^63 has magnitude 2^63 which needs 64 bits)
	nat.SetBytes(natBytes).Resize(len(b) * 8)
	nat.Add(&nat, new(saferith.Nat).SetUint64(uint64(sign)), len(b)*8)
	(*saferith.Int)(i).SetNat(&nat)
	(*saferith.Int)(i).Neg(saferith.Choice(sign))
}

// Increment sets i = i + 1.
func (i *Int) Increment() {
	i.Add(i, IntOne())
}

// Decrement sets i = i - 1.
func (i *Int) Decrement() {
	i.Sub(i, IntOne())
}

// Lsh sets i = x << shift.
func (i *Int) Lsh(x *Int, shift uint) {
	i.LshCap(x, shift, -1)
}

// LshCap sets i = x << shift with given capacity.
func (i *Int) LshCap(x *Int, shift uint, capacity int) {
	xAbs := (*saferith.Int)(x).Abs()
	xSign := (*saferith.Int)(x).IsNegative()
	xAbs.Lsh(xAbs, shift, capacity)
	(*saferith.Int)(i).SetNat(xAbs)
	// Preserve sign
	(*saferith.Int)(i).Neg(xSign)
}

// Rsh sets i = x >> shift.
func (i *Int) Rsh(x *Int, shift uint) {
	i.RshCap(x, shift, -1)
}

// RshCap sets i = x >> shift with given capacity.
// if capacity < 0, capacity will be x.AnnouncedLen() - shift.
func (i *Int) RshCap(x *Int, shift uint, capacity int) {
	xAbs := (*saferith.Int)(x).Abs()
	xSign := (*saferith.Int)(x).IsNegative()
	xAbs.Rsh(xAbs, shift, capacity)
	(*saferith.Int)(i).SetNat(xAbs)
	// Preserve sign
	(*saferith.Int)(i).Neg(xSign)
}

// Resize resizes i to have the given capacity.
// When capacity < 0, use the current announced length
// When capacity >= 0, use the provided capacity.
func (i *Int) Resize(capacity int) {
	if capacity < 0 {
		capacity = i.AnnouncedLen()
	}

	(*saferith.Int)(i).Resize(capacity)
}

// Coprime returns 1 if gcd(|i|, |rhs|) == 1.
func (i *Int) Coprime(rhs *Int) ct.Bool {
	var iNat, rhsNat Nat
	iNat.Abs(i)
	rhsNat.Abs(rhs)
	return iNat.Coprime(&rhsNat)
}

// IsProbablyPrime returns 1 if i is probably prime and non-negative.
func (i *Int) IsProbablyPrime() ct.Bool {
	var iNat Nat
	iNat.Abs(i)
	return iNat.IsProbablyPrime() & i.IsNegative().Not()
}

// Select sets i = x0 if choice == 0, or i = x1 if choice == 1,
// using only arithmetic on Int (no ct slice helpers).
func (i *Int) Select(choice ct.Choice, x0, x1 *Int) {
	var abs saferith.Nat
	abs.CondAssign(saferith.Choice(choice.Not()), (*saferith.Int)(x0).Abs())
	abs.CondAssign(saferith.Choice(choice), (*saferith.Int)(x1).Abs())
	sign := ct.CSelectInt(choice, (*saferith.Int)(x0).IsNegative(), (*saferith.Int)(x1).IsNegative())

	(*saferith.Int)(i).SetNat(&abs)
	(*saferith.Int)(i).Neg(sign)
}

// CondAssign sets i = x iff choice == 1, otherwise leaves i unchanged.
func (i *Int) CondAssign(choice ct.Choice, x *Int) {
	i.Select(choice, i, x)
}

// CondNeg negates i iff choice == 1.
func (i *Int) CondNeg(choice ct.Choice) {
	(*saferith.Int)(i).Neg(saferith.Choice(choice))
}

// Equal returns 1 if i == rhs.
func (i *Int) Equal(rhs *Int) ct.Bool {
	return ct.Bool((*saferith.Int)(i).Eq((*saferith.Int)(rhs)))
}

// Compare compares i and rhs and returns (lt, eq, gt) where each is 1 or 0.
func (i *Int) Compare(rhs *Int) (lt, eq, gt ct.Bool) {
	// Sign bits (0/1).
	aNeg := i.IsNegative()
	bNeg := rhs.IsNegative()

	// Magnitude comparison on |i|, |rhs|.
	var iAbs, rhsAbs Nat
	iAbs.Abs(i)
	rhsAbs.Abs(rhs)
	ltM, eqM, gtM := iAbs.Compare(&rhsAbs)

	// sameSign = 1 iff signs are equal, diffSign = 1 iff they differ.
	sameSign := (aNeg ^ bNeg).Not()
	diffSign := sameSign.Not()

	// bothNeg = 1 iff both are negative.
	bothNeg := sameSign & aNeg

	// If same sign:
	//   - both non-negative: ordering = magnitude ordering
	//   - both negative:     ordering = reversed magnitude ordering
	//
	// ltSame = (bothNeg ? gtM : ltM)
	// gtSame = (bothNeg ? ltM : gtM)
	ltSame := ct.CSelectInt(bothNeg, ltM, gtM)
	gtSame := ct.CSelectInt(bothNeg, gtM, ltM)

	// Only use these when signs match.
	ltSame &= sameSign
	gtSame &= sameSign
	eqSame := sameSign & eqM

	// If different signs, negative < non-negative.
	ltDiff := diffSign & aNeg
	gtDiff := diffSign & bNeg

	lt = ltSame | ltDiff
	gt = gtSame | gtDiff
	eq = eqSame
	return lt, eq, gt
}

// Uint64 returns the absolute value of i as a uint64.
func (i *Int) Uint64() uint64 {
	var iAbs Nat
	iAbs.Abs(i)
	return iAbs.Uint64()
}

// SetUint64 sets i = x.
func (i *Int) SetUint64(x uint64) {
	(*saferith.Int)(i).SetUint64(x)
}

// Int64 returns the int64 value of i.
func (i *Int) Int64() int64 {
	var iAbs Nat
	iAbs.Abs(i)
	abs := int64(iAbs.Uint64())
	return ct.CSelectInt(i.IsNegative(), abs, -abs)
}

// SetInt64 sets i = x.
func (i *Int) SetInt64(x int64) {
	ux := uint64(x)

	// mask = 0x000...0 if x >= 0, 0xFFF...F if x < 0
	mask := uint64(x >> 63)

	// mag = |x| as uint64, safe for MinInt64:
	//   x >= 0: mask = 0          => (ux ^ 0)      - 0      = ux
	//   x < 0 : mask = 0xFFFF..FF => (ux ^ mask)   - mask   = (~ux) + 1
	mag := (ux ^ mask) - mask

	(*saferith.Int)(i).SetUint64(mag)

	// sign bit = 1 iff x < 0, else 0
	signBit := mask & 1
	// Use 64 bits to accommodate MinInt64 which has magnitude 2^63
	(*saferith.Int)(i).Neg(saferith.Choice(signBit)).Resize(64)
}

// TrueLen returns the exact number of bits required to represent i.
func (i *Int) TrueLen() int {
	return (*saferith.Int)(i).TrueLen()
}

// AnnouncedLen returns the announced length in bits of i. Safe to be used publicly.
func (i *Int) AnnouncedLen() int {
	return (*saferith.Int)(i).AnnouncedLen()
}

// IsOdd returns 1 if i is odd.
func (i *Int) IsOdd() ct.Bool {
	var iAbs Nat
	iAbs.Abs(i)
	return iAbs.IsOdd()
}

// IsEven returns 1 if i is even.
func (i *Int) IsEven() ct.Bool {
	return i.IsOdd().Not()
}

// String returns the hex string representation of i.
func (i *Int) String() string {
	return (*saferith.Int)(i).String()
}

// HashCode returns a hash code for i.
func (i *Int) HashCode() base.HashCode {
	return base.DeriveHashCode(i.Bytes())
}

// Big returns a big.Int representation of i.
func (i *Int) Big() *big.Int {
	return (*saferith.Int)(i).Big()
}

// And sets i = x & y.
// For signed integers, this operates on the two's complement representation.
func (i *Int) And(x, y *Int) {
	i.AndCap(x, y, -1)
}

// AndCap sets i = x & y with capacity capacity.
// For signed integers, this operates on the two's-complement representation.
func (i *Int) AndCap(x, y *Int, capacity int) {
	if capacity < 0 {
		capacity = max(x.AnnouncedLen(), y.AnnouncedLen())
	}

	var xClone, yClone Int
	xClone.Set(x)
	xClone.Resize(capacity)
	yClone.Set(y)
	yClone.Resize(capacity)

	xBytes := xClone.TwosComplementBEBytes()
	yBytes := yClone.TwosComplementBEBytes()
	zBytes := make([]byte, len(xBytes))
	ct.AndBytes(zBytes, xBytes, yBytes)
	i.SetTwosComplementBEBytes(zBytes)
}

// Or sets i = x | y.
// For signed integers, this operates on the two's complement representation.
func (i *Int) Or(x, y *Int) {
	i.OrCap(x, y, -1)
}

// OrCap sets i = x | y with a given capacity.
func (i *Int) OrCap(x, y *Int, capacity int) {
	if capacity < 0 {
		capacity = max(x.AnnouncedLen(), y.AnnouncedLen())
	}

	var xClone, yClone Int
	xClone.Set(x)
	xClone.Resize(capacity)
	yClone.Set(y)
	yClone.Resize(capacity)

	xBytes := xClone.TwosComplementBEBytes()
	yBytes := yClone.TwosComplementBEBytes()
	zBytes := make([]byte, len(xBytes))
	ct.OrBytes(zBytes, xBytes, yBytes)
	i.SetTwosComplementBEBytes(zBytes)
}

// Xor sets i = x ^ y.
// For signed integers, this operates on the two's complement representation.
func (i *Int) Xor(x, y *Int) {
	i.XorCap(x, y, -1)
}

// XorCap sets i = x ^ y with the given capacity.
func (i *Int) XorCap(x, y *Int, capacity int) {
	if capacity < 0 {
		capacity = max(x.AnnouncedLen(), y.AnnouncedLen())
	}

	var xClone, yClone Int
	xClone.Set(x)
	xClone.Resize(capacity)
	yClone.Set(y)
	yClone.Resize(capacity)

	xBytes := xClone.TwosComplementBEBytes()
	yBytes := yClone.TwosComplementBEBytes()
	zBytes := make([]byte, len(xBytes))
	ct.XorBytes(zBytes, xBytes, yBytes)
	i.SetTwosComplementBEBytes(zBytes)
	// Don't resize - result may need more bits than inputs
}

// Not sets i = ^x.
// For signed integers, this is equivalent to -(x+1) due to two's complement.
func (i *Int) Not(x *Int) {
	i.NotCap(x, -1)
}

// NotCap sets i = ^x with a given capacity.
// For signed integers, this is equivalent to -(x+1) due to two's complement.
func (i *Int) NotCap(x *Int, capacity int) {
	if capacity < 0 {
		capacity = x.AnnouncedLen()
	}

	var xClone Int
	xClone.Set(x)
	xClone.Resize(capacity)

	xBytes := xClone.TwosComplementBEBytes()
	zBytes := make([]byte, len(xBytes))
	ct.NotBytes(zBytes, xBytes)
	i.SetTwosComplementBEBytes(zBytes)
	// Don't resize down - NOT may produce a value that needs more bits
	// (e.g., NOT(2^63-1) = -2^63 needs 64 bits for magnitude)
}

// SetRandomRangeLH sets i to a random integer in [lowInclusive, highExclusive).
func (i *Int) SetRandomRangeLH(lowInclusive, highExclusive *Int, prng io.Reader) error {
	var errs []error
	if lowInclusive == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("lowInclusive must not be nil"))
	}
	if highExclusive == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("highExclusive must not be nil"))
	}
	if prng == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("prng must not be nil"))
	}
	if lt, _, _ := lowInclusive.Compare(highExclusive); lt == ct.False {
		errs = append(errs, ErrInvalidArgument.WithMessage("highExclusive must be greater than lowInclusive"))
	}
	if len(errs) > 0 {
		return errs2.Join(errs...)
	}

	// Compute interval = highExclusive - lowInclusive (always positive since low < high)
	var interval Int
	interval.Sub(highExclusive, lowInclusive)

	// Generate random value in [0, interval) using Nat's method
	var intervalAbs, r Nat
	intervalAbs.Abs(&interval)
	err := r.SetRandomRangeH(&intervalAbs, prng)
	if err != nil {
		return errs2.Wrap(err)
	}

	// Result = lowInclusive + r
	var rInt Int
	rInt.SetNat(&r)
	i.Add(lowInclusive, &rInt)
	return nil
}

// TwosComplementBEBytes returns the two's-complement big-endian byte representation of i.
func (i *Int) TwosComplementBEBytes() []byte {
	// keep extra bit for sign
	capacityBits := i.AnnouncedLen() + 1
	capacityBytes := (capacityBits + 7) / 8

	iSign := (*saferith.Int)(i).IsNegative()
	iAbsBytes := make([]byte, capacityBytes)
	iAbsNotBytes := make([]byte, capacityBytes)
	(*saferith.Int)(i).Abs().FillBytes(iAbsBytes)
	ct.NotBytes(iAbsNotBytes, iAbsBytes)

	natBytes := make([]byte, capacityBytes)
	subtle.ConstantTimeCopy(int(iSign^0b1), natBytes, iAbsBytes)
	subtle.ConstantTimeCopy(int(iSign), natBytes, iAbsNotBytes)
	var nat saferith.Nat
	nat.SetBytes(natBytes)
	nat.Add(&nat, new(saferith.Nat).SetUint64(uint64(iSign)).Resize(1), capacityBytes*8)
	nat.FillBytes(natBytes)
	return natBytes
}
