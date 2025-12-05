package num

import (
	"io"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

var (
	zOnce     sync.Once
	zInstance *Integers
)

// Z returns the singleton instance of the Integers structure.
func Z() *Integers {
	zOnce.Do(func() {
		zInstance = &Integers{}
	})
	return zInstance
}

// Integers implements the algebra.Structure interface for the ring of integers Z.
type Integers struct{}

func (*Integers) Name() string {
	return "Z"
}

// Order returns the (infinite) order of the integers.
func (*Integers) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

// Characteristic returns the characteristic of the integers, which is 0.
func (*Integers) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

// OpIdentity returns the additive identity element (zero) of the integers.
func (zs *Integers) OpIdentity() *Int {
	return zs.Zero()
}

// Zero returns the zero element of the integers.
func (*Integers) Zero() *Int {
	return &Int{v: numct.IntZero()}
}

// One returns the multiplicative identity element (one) of the integers.
func (*Integers) One() *Int {
	return &Int{v: numct.IntOne()}
}

// IsSemiDomain returns true, indicating that the integers form a semi-domain (no zero divisors).
func (*Integers) IsSemiDomain() bool {
	return true
}

// FromUint64 creates an integer from a uint64 value.
func (*Integers) FromUint64(value uint64) *Int {
	return &Int{v: numct.NewIntFromUint64(value)}
}

// FromBig creates an integer from a big.Int value.
func (zs *Integers) FromBig(value *big.Int) (*Int, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value.Sign() == 0 {
		return zs.Zero(), nil
	}
	// Use numct.NewIntFromBig which correctly handles sign
	return &Int{v: numct.NewIntFromBig(value, value.BitLen())}, nil
}

// FromNatPlus creates an integer from a NatPlus value.
func (zs *Integers) FromNatPlus(value *NatPlus) (*Int, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return zs.FromNatCT(value.Value())
}

// FromNat creates an integer from a Nat value.
func (zs *Integers) FromNat(value *Nat) (*Int, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return zs.FromNatCT(value.Value())
}

// FromNatCT creates an integer from a numct.Nat value.
func (*Integers) FromNatCT(value *numct.Nat) (*Int, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	result := new(numct.Int)
	result.SetNat(value)
	return &Int{v: result}, nil
}

// FromIntCT creates an integer from a numct.Int value.
func (*Integers) FromIntCT(value *numct.Int) (*Int, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Int{v: value.Clone()}, nil
}

// FromInt64 creates an integer from an int64 value.
func (*Integers) FromInt64(value int64) *Int {
	return &Int{v: numct.NewInt(value)}
}

// FromCardinal creates an integer from a cardinal.Cardinal value.
func (zs *Integers) FromCardinal(value cardinal.Cardinal) (*Int, error) {
	n, err := N().FromCardinal(value)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return zs.FromNat(n)
}

// FromBytes creates an integer from its byte representation.
func (*Integers) FromBytes(input []byte) (*Int, error) {
	if len(input) == 0 {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Int{v: numct.NewIntFromBytes(input)}, nil
}

// FromUint creates an integer from a Uint value.
func (zs *Integers) FromUint(input *Uint) (*Int, error) {
	if input == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return zs.FromNatCT(input.v)
}

// FromRat creates an integer from a Rat value, if the Rat is an integer.
func (*Integers) FromRat(input *Rat) (*Int, error) {
	if input == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	canonical := input.Canonical()
	if !canonical.IsInt() {
		return nil, ErrUndefined.WithStackFrame()
	}
	return canonical.a.Clone(), nil
}

// FromUintSymmetric creates an integer from a Uint value using symmetric representation.
func (*Integers) FromUintSymmetric(input *Uint) (*Int, error) {
	if input == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	var v numct.Int
	input.m.ModSymmetric(&v, input.v)
	return &Int{v: &v}, nil
}

// Random generates a random integer in the range [lowInclusive, highExclusive).
func (*Integers) Random(lowInclusive, highExclusive *Int, prng io.Reader) (*Int, error) {
	var v numct.Int
	if err := v.SetRandomRangeLH(lowInclusive.v, highExclusive.v, prng); err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Int{v: &v}, nil
}

// ElementSize returns -1 indicating that the size of integer elements is unbounded.
func (*Integers) ElementSize() int {
	return -1
}

// ScalarStructure returns the structure of the scalars, which is also the integers.
func (*Integers) ScalarStructure() algebra.Structure[*Int] {
	return Z()
}

// Int represents an integer in the ring of integers Z.
type Int struct {
	v *numct.Int
}

// Value returns the underlying numct.Int value of the integer.
func (i *Int) Value() *numct.Int {
	return i.v
}

func (*Int) isValid(x *Int) (*Int, error) {
	if x == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return x, nil
}

// Structure returns the algebraic structure of the integers.
func (i *Int) Structure() algebra.Structure[*Int] {
	return Z()
}

// Op performs addition of two integers.
func (i *Int) Op(other *Int) *Int {
	return i.Add(other)
}

// TryOpInv returns the additive inverse of the integer.
func (i *Int) TryOpInv() (*Int, error) {
	return i.OpInv(), nil
}

// OpInv returns the additive inverse of the integer.
func (i *Int) OpInv() *Int {
	return i.Neg()
}

// OtherOp performs multiplication of two integers.
func (i *Int) OtherOp(other *Int) *Int {
	return i.Mul(other)
}

// Add performs addition of two integers.
func (i *Int) Add(other *Int) *Int {
	errs2.Must1(i.isValid(other))
	v := new(numct.Int)
	v.Add(i.v, other.v)
	return &Int{v: v}
}

// TrySub performs subtraction of two integers.
func (i *Int) TrySub(other *Int) (*Int, error) {
	return i.Sub(other), nil
}

// Sub performs subtraction of two integers.
func (i *Int) Sub(other *Int) *Int {
	errs2.Must1(i.isValid(other))
	v := new(numct.Int)
	v.Sub(i.v, other.v)
	return &Int{v: v}
}

// Mul performs multiplication of two integers.
func (i *Int) Mul(other *Int) *Int {
	errs2.Must1(i.isValid(other))
	v := new(numct.Int)
	v.Mul(i.v, other.v)
	return &Int{v: v}
}

// Lsh performs a left shift operation on the integer.
func (i *Int) Lsh(shift uint) *Int {
	v := new(numct.Int)
	v.Lsh(i.v, shift)
	return &Int{v: v}
}

// Rsh performs a right shift operation on the integer.
func (i *Int) Rsh(shift uint) *Int {
	v := new(numct.Int)
	v.Rsh(i.v, shift)
	return &Int{v: v}
}

// IsInRange checks if the integer is within the range defined by the modulus.
func (i *Int) IsInRange(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	return modulus.ModulusCT().IsInRange(i.Abs().v) == ct.True
}

func (i *Int) IsInRangeSymmetric(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	return modulus.ModulusCT().IsInRangeSymmetric(i.v) == ct.True
}

// Mod returns the integer modulo the given NatPlus modulus.
func (i *Int) Mod(modulus *NatPlus) *Uint {
	out := new(numct.Nat)
	modulus.ModulusCT().ModI(out, i.v)
	return &Uint{v: out, m: modulus.ModulusCT()}
}

// IsPositive checks if the integer is positive.
func (i *Int) IsPositive() bool {
	return i.v.IsNegative()|i.v.IsZero() == ct.False
}

// Coprime checks if two integers are coprime.
func (i *Int) Coprime(other *Int) bool {
	errs2.Must1(i.isValid(other))
	return i.v.Coprime(other.v) == ct.True
}

// IsProbablyPrime checks if the integer is probably prime.
func (i *Int) IsProbablyPrime() bool {
	return i.v.IsProbablyPrime() == ct.True
}

// EuclideanDiv performs Euclidean division of the integer by another integer.
func (i *Int) EuclideanDiv(other *Int) (quot, rem *Int, err error) {
	errs2.Must1(i.isValid(other))
	vq, vr := new(numct.Int), new(numct.Int)
	// Since DivModCap doesn't exist for Int, compute quotient and remainder separately
	if ok := vq.Div(i.v, other.v); ok == ct.False {
		return nil, nil, ErrInexactDivision.WithStackFrame()
	}

	// Compute remainder: rem = i - other * quot
	temp := new(numct.Int)
	temp.Mul(other.v, vq)
	vr.Sub(i.v, temp)
	return &Int{v: vq}, &Int{v: vr}, nil
}

// EuclideanValuation returns the Euclidean valuation of the integer.
func (i *Int) EuclideanValuation() algebra.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(i.Abs().Value()))
}

// Abs returns the absolute value of the integer.
func (i *Int) Abs() *Nat {
	return &Nat{v: (*numct.Nat)((*saferith.Int)(i.v.Clone()).Abs())}
}

// IsNegative checks if the integer is negative.
func (i *Int) IsNegative() bool {
	return i.v.IsNegative() == ct.True
}

// IsUnit checks if the integer is a unit modulo the given NatPlus modulus.
func (i *Int) IsUnit(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	m, ok := numct.NewModulus(modulus.v)
	if ok == ct.False {
		panic(errs2.New("modulus is not valid"))
	}
	return m.IsUnit(i.Mod(modulus).v) == ct.True
}

// TryDiv performs exact division of the integer by another integer.
func (i *Int) TryDiv(other *Int) (*Int, error) {
	if _, err := i.isValid(other); err != nil {
		return nil, errs2.Wrap(err)
	}
	v := new(numct.Int)
	divisorMod, modOk := numct.NewModulus(other.v.Absed())
	if modOk != ct.True {
		return nil, errs2.New("failed to create modulus from divisor")
	}
	if ok := v.ExactDiv(i.v, divisorMod); ok != ct.True {
		return nil, ErrInexactDivision.WithStackFrame()
	}
	// ExactDiv only considers the sign of the dividend, not the divisor.
	// We need to negate if the divisor is negative (XOR the signs).
	if other.IsNegative() {
		v.Neg(v)
	}
	out := &Int{v: v}
	return i.isValid(out)
}

// TryInv attempts to compute the multiplicative inverse of the integer.
func (i *Int) TryInv() (*Int, error) {
	if i.Abs().IsOne() {
		return i.Clone(), nil
	}
	return nil, ErrUndefined.WithStackFrame()
}

// TryNeg attempts to compute the negation of the integer. It never fails.
func (i *Int) TryNeg() (*Int, error) {
	return i.Neg(), nil
}

// Neg computes the negation of the integer.
func (i *Int) Neg() *Int {
	v := new(numct.Int)
	v.Neg(i.v.Clone())
	return &Int{v: v}
}

// Double returns the integer multiplied by 2.
func (i *Int) Double() *Int {
	return i.Add(i)
}

// Square returns the square of the integer.
func (i *Int) Square() *Int {
	return i.Mul(i)
}

// Compare compares the integer with another integer.
func (i *Int) Compare(other *Int) base.Ordering {
	errs2.Must1(i.isValid(other))
	lt, eq, gt := i.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

// IsLessThanOrEqual checks if the integer is less than or equal to another integer.
func (i *Int) IsLessThanOrEqual(other *Int) bool {
	errs2.Must1(i.isValid(other))
	lt, eq, _ := i.v.Compare(other.v)
	return lt|eq == ct.True
}

// Equal checks if the integer is equal to another integer.
func (i *Int) Equal(other *Int) bool {
	errs2.Must1(i.isValid(other))
	return i.v.Equal(other.v) == ct.True
}

// IsOpIdentity checks if the integer is the additive identity (zero).
func (i *Int) IsOpIdentity() bool {
	return i.IsZero()
}

// ScalarOp performs scalar multiplication of the integer by another integer.
func (i *Int) ScalarOp(other *Int) *Int {
	return i.Mul(other)
}

// IsTorsionFree returns true, indicating that the integers are torsion-free.
func (i *Int) IsTorsionFree() bool {
	return true
}

// ScalarMul performs scalar multiplication of the integer by another integer.
func (i *Int) ScalarMul(other *Int) *Int {
	return i.Mul(other)
}

// IsZero checks if the integer is zero.
func (i *Int) IsZero() bool {
	return i.v.IsZero() == ct.True
}

// IsOne checks if the integer is one.
func (i *Int) IsOne() bool {
	return i.v.IsOne() == ct.True
}

// HashCode returns the hash code of the integer.
func (i *Int) HashCode() base.HashCode {
	return i.v.HashCode()
}

// Clone creates a copy of the integer.
func (i *Int) Clone() *Int {
	return &Int{v: i.v.Clone()}
}

// String returns the string representation of the integer.
func (i *Int) String() string {
	return i.v.String()
}

// Increment returns the integer incremented by one.
func (i *Int) Increment() *Int {
	return i.Add(Z().One())
}

// Decrement returns the integer decremented by one.
func (i *Int) Decrement() *Int {
	return i.Sub(Z().One())
}

// Rat converts the integer to a rational number.
func (i *Int) Rat() *Rat {
	return &Rat{a: i.Clone(), b: NPlus().One()}
}

// Bytes returns the byte representation of the integer.
func (i *Int) Bytes() []byte {
	return i.v.Bytes()
}

// Bit returns the value of the i-th bit of the integer.
func (n *Int) Bit(i uint) byte {
	return (n.v.Bit(i))
}

// IsEven checks if the integer is even.
func (n *Int) IsEven() bool {
	return n.v.IsEven() == ct.True
}

// IsOdd checks if the integer is odd.
func (n *Int) IsOdd() bool {
	return n.v.IsOdd() == ct.True
}

// Big converts the integer to a big.Int.
func (i *Int) Big() *big.Int {
	return i.v.Big()
}

// Lift returns a copy of the integer (identity function for integers).
func (i *Int) Lift() *Int {
	return i.Clone()
}

// Cardinal returns the cardinality of the absolute value of the integer.
func (i *Int) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(i.Abs().v))
}

// TrueLen returns the true length of the integer in bytes.
func (i *Int) TrueLen() int {
	return i.v.TrueLen()
}

// AnnouncedLen returns the announced length of the integer in bytes.
func (i *Int) AnnouncedLen() int {
	return i.v.AnnouncedLen()
}
