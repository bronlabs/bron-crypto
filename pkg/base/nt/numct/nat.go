package numct

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// NatZero returns a new Nat representing zero.
func NatZero() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(0).Resize(1))
}

// NatOne returns a new Nat representing one.
func NatOne() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(1).Resize(1))
}

// NatTwo returns a new Nat representing two.
func NatTwo() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(2).Resize(2))
}

// NatThree returns a new Nat representing three.
func NatThree() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(3).Resize(2))
}

// NewNat returns a new Nat initialized to the given uint64 value.
func NewNat(value uint64) *Nat {
	n := new(Nat)
	n.SetUint64(value)
	return n
}

// NewNatFromSaferith creates a Nat from a saferith.Nat.
func NewNatFromSaferith(n *saferith.Nat) *Nat {
	return (*Nat)(n)
}

// NewNatFromBytes creates a Nat from a big-endian byte slice.
func NewNatFromBytes(n []byte) *Nat {
	return (*Nat)(new(saferith.Nat).SetBytes(n))
}

// NewNatFromBig creates a Nat from a big.Int with the given capacity.
func NewNatFromBig(n *big.Int, cap int) *Nat {
	return (*Nat)(new(saferith.Nat).SetBig(n, int(cap)))
}

// Nat is a wrapper around saferith.Nat providing additional methods and occasional improvements.
// This implements the low level constant time interfaces that fiat-crypto implements.
type Nat saferith.Nat

// Set sets n to the value of v.
func (n *Nat) Set(v *Nat) {
	*n = *v
}

// SetZero sets n to zero.
func (n *Nat) SetZero() {
	n.Set(NatZero())
}

// SetOne sets n to one.
func (n *Nat) SetOne() {
	n.Set(NatOne())
}

// Clone returns a copy of n.
func (n *Nat) Clone() *Nat {
	return (*Nat)((*saferith.Nat)(n).Clone())
}

// Lift converts n to an Int.
func (n *Nat) Lift() *Int {
	return (*Int)(new(saferith.Int).SetNat((*saferith.Nat)(n)))
}

// Add sets n = lhs + rhs.
func (n *Nat) Add(lhs, rhs *Nat) {
	n.AddCap(lhs, rhs, -1)
}

// AddCap sets n = lhs + rhs modulo 2^cap with capacity cap.
// if cap < 0, capacity will be max(lhs.AnnouncedLen(), rhs.AnnouncedLen()) + 1
func (n *Nat) AddCap(lhs, rhs *Nat, cap int) {
	(*saferith.Nat)(n).Add((*saferith.Nat)(lhs), (*saferith.Nat)(rhs), cap)
}

// Sub sets n = lhs - rhs modulo 2^cap.
// if cap < 0, capacity will be max(lhs.AnnouncedLen(), rhs.AnnouncedLen()) + 1
func (n *Nat) SubCap(lhs, rhs *Nat, cap int) {
	(*saferith.Nat)(n).Sub((*saferith.Nat)(lhs), (*saferith.Nat)(rhs), cap)
}

// Mul sets n = lhs * rhs.
func (n *Nat) Mul(lhs, rhs *Nat) {
	n.MulCap(lhs, rhs, -1)
}

// MulCap sets n = lhs * rhs modulo 2^cap.
// if cap < 0, capacity will be lhs.AnnouncedLen() + rhs.AnnouncedLen()
func (n *Nat) MulCap(lhs, rhs *Nat, cap int) {
	(*saferith.Nat)(n).Mul((*saferith.Nat)(lhs), (*saferith.Nat)(rhs), cap)
}

// DivCap sets n = numerator / denominator with capacity cap.
// if cap < 0, capacity will be numerator.AnnouncedLen() - denominator.BitLen() + 2
// It returns ok=true if the division was successful, ok=false otherwise (e.g., division by zero).
func (n *Nat) DivCap(numerator *Nat, denominator *Modulus, cap int) (ok ct.Bool) {
	ok = utils.BoolTo[ct.Bool](denominator != nil)
	n.Set((*Nat)(new(saferith.Nat).Div(
		(*saferith.Nat)(numerator),
		denominator.Saferith(),
		cap,
	)))
	return ok
}

// ExactDiv sets n = numerator / denominator if the division is exact (no remainder).
// It returns ok=true if the division was exact, ok=false otherwise.
// If the division is not exact, n is not modified.
func (n *Nat) ExactDiv(numerator *Nat, denominator *Modulus) (ok ct.Bool) {
	var q, r Nat
	ok = DivModCap(&q, &r, numerator, denominator, -1)
	isExact := r.IsZero()
	// Only update n if division was exact
	n.CondAssign(ct.Choice(ok&isExact), &q)
	return ok & isExact
}

// Double sets n = x + x.
func (n *Nat) Double(x *Nat) {
	n.Add(x, x)
}

// Increment increments n by 1.
func (n *Nat) Increment() {
	n.Add(n, NatOne())
}

// Decrement decrements n by 1.
func (n *Nat) Decrement() {
	(*saferith.Nat)(n).Sub((*saferith.Nat)(n), (*saferith.Nat)(NatOne()), -1)
}

// Bit returns the i-th bit of n.
func (n *Nat) Bit(i uint) byte {
	return (*saferith.Nat)(n).Byte(int(i/8)) >> (i % 8) & 1
}

// Byte returns the i-th byte of n.
func (n *Nat) Byte(i uint) byte {
	return (*saferith.Nat)(n).Byte(int(i))
}

// Compare compares n with rhs and returns lt, eq, gt (each will be 1 or 0).
func (n *Nat) Compare(rhs *Nat) (lt, eq, gt ct.Bool) { // TODO: swap order
	sgt, seq, slt := (*saferith.Nat)(n).Cmp((*saferith.Nat)(rhs))
	return ct.Bool(slt), ct.Bool(seq), ct.Bool(sgt)
}

// Equal returns 1 if n == rhs.
func (n *Nat) Equal(rhs *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Eq((*saferith.Nat)(rhs)))
}

// Less returns 1 if n < rhs.
func (n *Nat) IsZero() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).EqZero())
}

// IsNonZero returns 1 if n != 0.
func (n *Nat) IsNonZero() ct.Bool {
	return n.IsZero().Not()
}

// IsOne returns 1 if n == 1.
func (n *Nat) IsOne() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Eq((*saferith.Nat)(NatOne())))
}

// Coprime returns 1 if n is coprime to x.
func (n *Nat) Coprime(x *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Coprime((*saferith.Nat)(x)))
}

// String returns the hex string representation of n.
func (n *Nat) String() string {
	return (*saferith.Nat)(n).String()
}

// TrueLen returns exact number of bits required to represent n. Note that it would leak required number of zero bits in n.
func (n *Nat) TrueLen() uint {
	return uint((*saferith.Nat)(n).TrueLen())
}

// AnnouncedLen returns the announced length in bits of n. Safe to be used publicly.
func (n *Nat) AnnouncedLen() uint {
	return uint((*saferith.Nat)(n).AnnouncedLen())
}

// Select sets n = x0 if choice == 0, n = x1 if choice == 1.
func (n *Nat) Select(choice ct.Choice, x0, x1 *Nat) {
	n.Set(x0)
	(*saferith.Nat)(n).CondAssign(saferith.Choice(choice), (*saferith.Nat)(x1))
}

// CondAssign sets n = x if choice == 1.
func (n *Nat) CondAssign(choice ct.Choice, x *Nat) {
	(*saferith.Nat)(n).CondAssign(saferith.Choice(choice), (*saferith.Nat)(x))
}

// IsOdd returns 1 if n is odd.
func (n *Nat) IsOdd() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Byte(0) & 0b1)
}

// IsEven returns 1 if n is even.
func (n *Nat) IsEven() ct.Bool {
	return n.IsOdd().Not()
}

// Resize resizes n to have capacity cap.
// When cap < 0, use the current announced length
// When cap >= 0, use the provided cap
func (n *Nat) Resize(cap int) {
	(*saferith.Nat)(n).Resize(ct.CSelectInt(ct.GreaterOrEqual(cap, 0), int(n.AnnouncedLen()), cap))
}

// Lsh left shifts n by shift bits.
func (n *Nat) Lsh(x *Nat, shift uint) {
	n.LshCap(x, shift, -1)
}

// IsProbablyPrime returns 1 if n is probably prime, by applying a BPSW test.
func (n *Nat) IsProbablyPrime() ct.Bool {
	return utils.BoolTo[ct.Bool]((*saferith.Nat)(n).Big().ProbablyPrime(0))
}

// LshCap left shifts n by shift bits with capacity cap.
// if cap < 0, capacity will be x.AnnouncedLen() + shift.
func (n *Nat) LshCap(x *Nat, shift uint, cap int) {
	(*saferith.Nat)(n).Lsh((*saferith.Nat)(x), shift, cap)
}

// Rsh right shifts n by shift bits.
func (n *Nat) Rsh(x *Nat, shift uint) {
	n.RshCap(x, shift, -1)
}

// RshCap right shifts n by shift bits with capacity cap.
// if cap < 0, capacity will be x.AnnouncedLen() - shift.
func (n *Nat) RshCap(x *Nat, shift uint, cap int) {
	(*saferith.Nat)(n).Rsh((*saferith.Nat)(x), shift, cap)
}

// Uint64 returns the uint64 representation of n.
func (n *Nat) Uint64() uint64 {
	return (*saferith.Nat)(n).Uint64()
}

// SetUint64 sets n to the given uint64 value.
func (n *Nat) SetUint64(x uint64) {
	(*saferith.Nat)(n).SetUint64(x)
}

// Bytes returns the big-endian byte representation of n.
func (n *Nat) Bytes() []byte {
	return (*saferith.Nat)(n).Bytes()
}

// BytesBE returns the big-endian byte representation of n.
func (n *Nat) BytesBE() []byte {
	return n.Bytes()
}

// SetBytes sets n from the big-endian byte slice data.
func (n *Nat) SetBytes(data []byte) (ok ct.Bool) {
	(*saferith.Nat)(n).SetBytes(data)
	return ct.True
}

// FillBytes fills buf with the big-endian byte representation of n and returns buf.
func (n *Nat) FillBytes(buf []byte) []byte {
	return (*saferith.Nat)(n).FillBytes(buf)
}

// HashCode returns a hash code for n.
func (n *Nat) HashCode() base.HashCode {
	return base.DeriveHashCode(n.Bytes())
}

// Big returns the big.Int representation of n.
func (n *Nat) Big() *big.Int {
	return (*saferith.Nat)(n).Big()
}

// And sets n = x & y and returns n.
func (n *Nat) And(x, y *Nat) {
	n.AndCap(x, y, -1)
}

// AndCap sets n = x & y with capacity cap.
func (n *Nat) AndCap(x, y *Nat, cap int) {
	// Get byte representations
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// For AND, the result length is at most the minimum of the two lengths
	// Use the maximum to ensure we don't lose data with internal representation
	xLen := len(xBytes)
	yLen := len(yBytes)
	maxLen := ct.Max(xLen, yLen)

	// Pad both to the same length (for big-endian, pad on the left)
	xPadded := sliceutils.PadToLeft(xBytes, maxLen-xLen)
	yPadded := sliceutils.PadToLeft(yBytes, maxLen-yLen)

	// Perform AND
	result := make([]byte, maxLen)
	ct.AndBytes(result, xPadded, yPadded)

	// Set the result
	(*saferith.Nat)(n).SetBytes(result)
	n.Resize(cap)
}

// Or sets n = x | y.
func (n *Nat) Or(x, y *Nat) {
	n.OrCap(x, y, -1)
}

// OrCap sets n = x | y with capacity cap.
func (n *Nat) OrCap(x, y *Nat, cap int) {
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// Use constant-time max for result length (OR uses longer length)
	xLen := len(xBytes)
	yLen := len(yBytes)
	resultLen := ct.Max(xLen, yLen)

	// Use PadLeft for big-endian padding
	xPadded := sliceutils.PadToLeft(xBytes, resultLen-xLen)
	yPadded := sliceutils.PadToLeft(yBytes, resultLen-yLen)

	result := make([]byte, resultLen)
	ct.OrBytes(result, xPadded, yPadded)

	(*saferith.Nat)(n).SetBytes(result)
	n.Resize(cap)
}

// Xor sets n = x ^ y.
func (n *Nat) Xor(x, y *Nat) {
	n.XorCap(x, y, -1)
}

// XorCap sets n = x ^ y with capacity cap.
func (n *Nat) XorCap(x, y *Nat, cap int) {
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// Use constant-time max for result length (XOR uses longer length)
	xLen := len(xBytes)
	yLen := len(yBytes)
	resultLen := ct.Max(xLen, yLen)

	// Use PadLeft for big-endian padding
	xPadded := sliceutils.PadToLeft(xBytes, resultLen-xLen)
	yPadded := sliceutils.PadToLeft(yBytes, resultLen-yLen)

	result := make([]byte, resultLen)
	ct.XorBytes(result, xPadded, yPadded)

	(*saferith.Nat)(n).SetBytes(result)
	n.Resize(cap)
}

// Not sets n = ^x.
func (n *Nat) Not(x *Nat) {
	n.NotCap(x, int(x.AnnouncedLen()))
}

// NotCap sets n = ^x with capacity cap.
// For compatibility with big.Int.Not, use the announced capacity of x.
func (n *Nat) NotCap(x *Nat, cap int) {
	xBytes := x.Bytes()

	// Determine the bit capacity to use
	// When cap < 0, use x's announced capacity
	bitCap := ct.CSelectInt(ct.GreaterOrEqual(cap, 0), int(x.AnnouncedLen()), cap)

	// Calculate byte length from bit capacity
	byteLen := (bitCap + 7) / 8

	// Allocate and pad input
	xPadded := sliceutils.PadToLeft(xBytes, byteLen-len(xBytes))

	// Apply NOT operation
	result := make([]byte, byteLen)
	ct.NotBytes(result, xPadded)

	(*saferith.Nat)(n).SetBytes(result)
	n.Resize(cap)
}

// Random sets n to a random value in the range [lowInclusive, highExclusive).
func (n *Nat) Random(lowInclusive, highExclusive *Nat, prng io.Reader) error {
	errs := []error{}
	if lowInclusive == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("lowInclusive must not be nil"))
	}
	if highExclusive == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("highExclusive must not be nil"))
	}
	if prng == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("prng must not be nil"))
	}
	var maxVal Nat
	maxVal.SubCap(highExclusive, lowInclusive, int(highExclusive.AnnouncedLen()))
	if maxVal.IsZero() == ct.True {
		errs = append(errs, ErrInvalidArgument.WithMessage("max must be greater than zero"))
	}
	if len(errs) > 0 {
		return errs2.Join(errs...)
	}

	randBig, err := crand.Int(prng, maxVal.Big())
	if err != nil {
		return errs2.AttachStackTrace(err)
	}

	n.AddCap(lowInclusive, NewNatFromBig(randBig, int(highExclusive.AnnouncedLen())), int(highExclusive.AnnouncedLen()))
	return nil
}

// DivModCap computes a / b and a % b, storing the results into outQuot and outRem.
// The cap parameter sets the announced capacity (in bits) for the quotient.
func DivModCap(outQuot, outRem, a *Nat, b *Modulus, cap int) (ok ct.Bool) {
	ok = outQuot.DivCap(a, b, cap)
	b.Mod(outRem, a)
	return ok
}
