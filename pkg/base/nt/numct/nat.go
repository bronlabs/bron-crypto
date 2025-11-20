package numct

import (
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

var (
	_ (internal.NatMutable[*Nat, *Modulus]) = (*Nat)(nil)
)

// DivModCap computes a / b and a % b, storing the results into outQuot and outRem.
// The cap parameter sets the announced capacity (in bits) for the quotient.
func DivModCap(outQuot, outRem, a *Nat, b *Modulus, cap int) (ok ct.Bool) {
	ok = outQuot.DivCap(a, b, cap)
	b.Mod(outRem, a)
	return ok
}

func NatZero() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(0).Resize(1))
}

func NatOne() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(1).Resize(1))
}

func NatTwo() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(2).Resize(2))
}

func NatThree() *Nat {
	return (*Nat)(new(saferith.Nat).SetUint64(3).Resize(2))
}

func NewNat(value uint64) *Nat {
	n := new(Nat)
	n.SetUint64(value)
	return n
}

func NewNatFromSaferith(n *saferith.Nat) *Nat {
	return (*Nat)(n)
}

func NewNatFromBytes(n []byte) *Nat {
	return (*Nat)(new(saferith.Nat).SetBytes(n))
}

func NewNatFromBig(n *big.Int, cap int) *Nat {
	return (*Nat)(new(saferith.Nat).SetBig(n, int(cap)))
}

type Nat saferith.Nat

func (n *Nat) Set(v *Nat) {
	*n = *v
}

func (n *Nat) SetZero() {
	n.Set(NatZero())
}

func (n *Nat) SetOne() {
	n.Set(NatOne())
}

func (n *Nat) Clone() *Nat {
	return (*Nat)((*saferith.Nat)(n).Clone())
}

func (n *Nat) Lift() *Int {
	return (*Int)(new(saferith.Int).SetNat((*saferith.Nat)(n)))
}

func (n *Nat) Add(lhs, rhs *Nat) {
	n.AddCap(lhs, rhs, -1)
}

func (n *Nat) AddCap(lhs, rhs *Nat, cap int) {
	(*saferith.Nat)(n).Add((*saferith.Nat)(lhs), (*saferith.Nat)(rhs), cap)
}

func (n *Nat) SubCap(lhs, rhs *Nat, cap int) {
	(*saferith.Nat)(n).Sub((*saferith.Nat)(lhs), (*saferith.Nat)(rhs), cap)
}

func (n *Nat) Mul(lhs, rhs *Nat) {
	n.MulCap(lhs, rhs, -1)
}

func (n *Nat) MulCap(lhs, rhs *Nat, cap int) {
	(*saferith.Nat)(n).Mul((*saferith.Nat)(lhs), (*saferith.Nat)(rhs), cap)
}

func (n *Nat) DivCap(numerator *Nat, denominator *Modulus, cap int) (ok ct.Bool) {
	ok = utils.BoolTo[ct.Bool](denominator != nil)
	n.Set((*Nat)(new(saferith.Nat).Div(
		(*saferith.Nat)(numerator),
		denominator.Saferith(),
		cap,
	)))
	return ok
}

func (n *Nat) ExactDiv(numerator *Nat, denominator *Modulus) (ok ct.Bool) {
	var q, r Nat
	ok = DivModCap(&q, &r, numerator, denominator, -1)
	isExact := r.IsZero()
	// Only update n if division was exact
	n.CondAssign(ct.Choice(ok&isExact), &q)
	return ok & isExact
}

func (n *Nat) Double(x *Nat) {
	n.Add(x, x)
}

func (n *Nat) Increment() {
	n.Add(n, NatOne())
}

func (n *Nat) Decrement() {
	(*saferith.Nat)(n).Sub((*saferith.Nat)(n), (*saferith.Nat)(NatOne()), -1)
}

func (n *Nat) Bit(i uint) byte {
	return (*saferith.Nat)(n).Byte(int(i/8)) >> (i % 8) & 1
}

func (n *Nat) Byte(i uint) byte {
	return (*saferith.Nat)(n).Byte(int(i))
}

func (n *Nat) Compare(rhs *Nat) (lt, eq, gt ct.Bool) {
	sgt, seq, slt := (*saferith.Nat)(n).Cmp((*saferith.Nat)(rhs))
	return ct.Bool(slt), ct.Bool(seq), ct.Bool(sgt)
}

func (n *Nat) Equal(rhs *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Eq((*saferith.Nat)(rhs)))
}

func (n *Nat) IsZero() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).EqZero())
}

func (n *Nat) IsNonZero() ct.Bool {
	return n.IsZero().Not()
}

func (n *Nat) IsOne() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Eq((*saferith.Nat)(NatOne())))
}

func (n *Nat) Coprime(x *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Coprime((*saferith.Nat)(x)))
}

func (n *Nat) String() string {
	return (*saferith.Nat)(n).String()
}

func (n *Nat) TrueLen() uint {
	return uint((*saferith.Nat)(n).TrueLen())
}

func (n *Nat) AnnouncedLen() uint {
	return uint((*saferith.Nat)(n).AnnouncedLen())
}

func (n *Nat) Select(choice ct.Choice, x0, x1 *Nat) {
	n.Set(x0)
	(*saferith.Nat)(n).CondAssign(saferith.Choice(choice), (*saferith.Nat)(x1))
}

func (n *Nat) CondAssign(choice ct.Choice, x *Nat) {
	(*saferith.Nat)(n).CondAssign(saferith.Choice(choice), (*saferith.Nat)(x))
}

func (n *Nat) IsOdd() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Byte(0) & 0b1)
}

func (n *Nat) IsEven() ct.Bool {
	return n.IsOdd().Not()
}

func (n *Nat) Resize(cap int) {
	// When cap < 0, use the current announced length
	// When cap >= 0, use the provided cap
	// CSelectInt(choice, x0, x1): returns x0 when choice=0, x1 when choice=1
	// GreaterOrEqual(cap, 0): returns 1 when cap >= 0
	// So: when cap >= 0 (choice=1), select cap (x1)
	//     when cap < 0 (choice=0), select announcedLen (x0)
	(*saferith.Nat)(n).Resize(ct.CSelectInt(ct.GreaterOrEqual(cap, 0), int(n.AnnouncedLen()), cap))
}

func (n *Nat) Lsh(x *Nat, shift uint) {
	n.LshCap(x, shift, -1)
}

func (n *Nat) IsProbablyPrime() ct.Bool {
	return utils.BoolTo[ct.Bool]((*saferith.Nat)(n).Big().ProbablyPrime(0))
}

func (n *Nat) LshCap(x *Nat, shift uint, cap int) {
	(*saferith.Nat)(n).Lsh((*saferith.Nat)(x), shift, cap)
}

func (n *Nat) Rsh(x *Nat, shift uint) {
	n.RshCap(x, shift, -1)
}

func (n *Nat) RshCap(x *Nat, shift uint, cap int) {
	(*saferith.Nat)(n).Rsh((*saferith.Nat)(x), shift, cap)
}

func (n *Nat) Uint64() uint64 {
	return (*saferith.Nat)(n).Uint64()
}

func (n *Nat) SetUint64(x uint64) {
	(*saferith.Nat)(n).SetUint64(x)
}

func (n *Nat) Bytes() []byte {
	return (*saferith.Nat)(n).Bytes()
}

func (n *Nat) BytesBE() []byte {
	return n.Bytes()
}

func (n *Nat) SetBytes(data []byte) (ok ct.Bool) {
	(*saferith.Nat)(n).SetBytes(data)
	return ct.True
}

func (n *Nat) FillBytes(buf []byte) []byte {
	return (*saferith.Nat)(n).FillBytes(buf)
}

func (n *Nat) HashCode() base.HashCode {
	return base.DeriveHashCode(n.Bytes())
}

func (n *Nat) Big() *big.Int {
	return (*saferith.Nat)(n).Big()
}

// And sets n = x & y and returns n.
func (n *Nat) And(x, y *Nat) {
	n.AndCap(x, y, -1)
}

// AndCap sets n = x & y with capacity cap and returns n.
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
	if cap >= 0 {
		n.Resize(cap)
	}
}

// Or sets n = x | y and returns n.
func (n *Nat) Or(x, y *Nat) {
	n.OrCap(x, y, -1)
}

// OrCap sets n = x | y with capacity cap and returns n.
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
	if cap >= 0 {
		n.Resize(cap)
	}
}

// Xor sets n = x ^ y and returns n.
func (n *Nat) Xor(x, y *Nat) {
	n.XorCap(x, y, -1)
}

// XorCap sets n = x ^ y with capacity cap and returns n.
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
	if cap >= 0 {
		n.Resize(cap)
	}
}

// Not sets n = ^x and returns n.
func (n *Nat) Not(x *Nat) {
	n.NotCap(x, -1)
}

// NotCap sets n = ^x with capacity cap and returns n.
// Note: The result depends on the capacity as it determines the bit width.
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
	if cap >= 0 {
		n.Resize(cap)
	}
}
