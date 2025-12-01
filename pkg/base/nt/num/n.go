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
	nOnce     sync.Once
	nInstance *NaturalNumbers
)

// N returns the singleton instance of the NaturalNumbers structure.
func N() *NaturalNumbers {
	nOnce.Do(func() {
		nInstance = &NaturalNumbers{}
	})
	return nInstance
}

// NaturalNumbers represents the set of natural numbers (non-negative integers).
type NaturalNumbers struct{}

// Name returns the name of the structure: "N".
func (*NaturalNumbers) Name() string {
	return "N"
}

// Characteristic returns the characteristic of the NaturalNumbers structure, which is 0.
func (*NaturalNumbers) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

// Order returns the order of the NaturalNumbers structure, which is infinite.
func (*NaturalNumbers) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

// Zero returns the additive identity element of the NaturalNumbers structure.
func (*NaturalNumbers) Zero() *Nat {
	return &Nat{v: numct.NatZero()}
}

// One returns the multiplicative identity element of the NaturalNumbers structure.
func (*NaturalNumbers) One() *Nat {
	return &Nat{v: numct.NatOne()}
}

// OpIdentity returns the identity element for the addition operation in the NaturalNumbers structure.
func (ns *NaturalNumbers) OpIdentity() *Nat {
	return ns.Zero()
}

// FromUint64 creates a Nat from a uint64 value.
func (ns *NaturalNumbers) FromUint64(value uint64) *Nat {
	return &Nat{v: numct.NewNat(value)}
}

// FromNatPlus creates a Nat from a NatPlus value, returning an error if the input is nil.
func (ns *NaturalNumbers) FromNatPlus(value *NatPlus) (*Nat, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Nat{v: value.v.Clone()}, nil
}

// FromBig creates a Nat from a big.Int value, returning an error if the input is nil or negative.
func (ns *NaturalNumbers) FromBig(value *big.Int) (*Nat, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value.Sign() < 0 {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	if value.Sign() == 0 {
		return ns.Zero(), nil
	}
	return ns.FromBytes(value.Bytes())
}

// FromRat creates a Nat from a Rat value, returning an error if Rat is not a non-negative integer.
func (ns *NaturalNumbers) FromRat(value *Rat) (*Nat, error) {
	vInt, err := Z().FromRat(value)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return ns.FromInt(vInt)
}

// FromNatCT creates a Nat from a numct.Nat value, returning an error if the input is nil.
func (ns *NaturalNumbers) FromNatCT(value *numct.Nat) (*Nat, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Nat{v: value.Clone()}, nil
}

// FromInt creates a Nat from an Int value, returning an error if the input is nil or negative.
func (ns *NaturalNumbers) FromInt(value *Int) (*Nat, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value.IsNegative() {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	if value.IsZero() {
		return ns.Zero(), nil
	}
	return value.Abs(), nil
}

// FromBytes creates a Nat from a byte slice, returning an error if the input is nil.
func (ns *NaturalNumbers) FromBytes(input []byte) (*Nat, error) {
	if input == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Nat{v: numct.NewNatFromBytes(input)}, nil
}

// FromBytesBE creates a Nat from a big-endian byte slice, returning an error if the input is nil.
func (ns *NaturalNumbers) FromBytesBE(input []byte) (*Nat, error) {
	return ns.FromBytes(input)
}

// FromCardinal creates a Nat from a cardinal.Cardinal value, returning an error if the input is nil or infinite.
func (ns *NaturalNumbers) FromCardinal(value cardinal.Cardinal) (*Nat, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if !value.IsFinite() {
		return nil, ErrUndefined.WithStackFrame()
	}
	if value.IsZero() {
		return ns.Zero(), nil
	}
	return &Nat{v: numct.NewNatFromBytes(value.Bytes())}, nil
}

// Random generates a random Nat in the range [lowInclusive, highExclusive), returning an error if highExclusive is nil.
func (ns *NaturalNumbers) Random(lowInclusive, highExclusive *Nat, prng io.Reader) (*Nat, error) {
	if lowInclusive == nil {
		lowInclusive = ns.Bottom()
	}
	var v numct.Nat
	if err := v.SetRandomRangeLH(lowInclusive.Value(), highExclusive.Value(), prng); err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Nat{v: &v}, nil
}

// Bottom returns the smallest element in the NaturalNumbers structure, which is 0.
func (ns *NaturalNumbers) Bottom() *Nat {
	return ns.Zero()
}

// ElementSize returns -1 indicating that elements of NaturalNumbers do not have a fixed size.
func (ns *NaturalNumbers) ElementSize() int {
	return -1
}

// ScalarStructure returns the regular semi-module structure of NaturalNumbers.
func (ns *NaturalNumbers) ScalarStructure() algebra.Structure[*Nat] {
	return N()
}

// Nat represents a natural number (non-negative integer).
type Nat struct {
	v *numct.Nat
}

func (*Nat) isValid(x *Nat) (*Nat, error) {
	if x == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return x, nil
}

// Structure returns the NaturalNumbers structure.
func (*Nat) Structure() algebra.Structure[*Nat] {
	return N()
}

// Value returns the underlying numct.Nat value of the Nat.
func (n *Nat) Value() *numct.Nat {
	if n == nil {
		return nil
	}
	return n.v
}

// Op performs the addition operation on two Nat values.
func (n *Nat) Op(other *Nat) *Nat {
	return n.Add(other)
}

// OtherOp performs the multiplication operation on two Nat values.
func (n *Nat) OtherOp(other *Nat) *Nat {
	return n.Mul(other)
}

// Add performs the addition of two Nat values.
func (n *Nat) Add(other *Nat) *Nat {
	errs2.Must1(n.isValid(other))
	v := new(numct.Nat)
	v.Add(n.v, other.v)
	return &Nat{v: v}
}

// Mul performs the multiplication of two Nat values.
func (n *Nat) Mul(other *Nat) *Nat {
	errs2.Must1(n.isValid(other))
	v := new(numct.Nat)
	v.Mul(n.v, other.v)
	return &Nat{v: v}
}

// Lsh performs a left shift operation on the Nat by the specified number of bits.
func (n *Nat) Lsh(shift uint) *Nat {
	v := new(numct.Nat)
	v.Lsh(n.v, shift)
	return &Nat{v: v}
}

// Rsh performs a right shift operation on the Nat by the specified number of bits.
func (n *Nat) Rsh(shift uint) *Nat {
	v := new(numct.Nat)
	v.Rsh(n.v, shift)
	return &Nat{v: v}
}

// TryOpInv attempts to compute the additive inverse of the Nat. It will always return an error since natural numbers do not have additive inverses.
func (n *Nat) TryOpInv() (*Nat, error) {
	return n.TryNeg()
}

// TryNeg attempts to compute the negation of the Nat. It will always return an error since natural numbers do not have negation.
func (n *Nat) TryNeg() (*Nat, error) {
	return nil, ErrUndefined.WithStackFrame()
}

// TrySub attempts to subtract another Nat from the current Nat. It returns an error if the result would not be a natural number.
func (n *Nat) TrySub(other *Nat) (*Nat, error) {
	if _, err := n.isValid(other); err != nil {
		return nil, errs2.Wrap(err)
	}
	if n.Compare(other).IsLessThan() {
		return nil, ErrUndefined.WithStackFrame()
	}
	v := new(numct.Nat)
	v.SubCap(n.v, other.v, -1)
	return &Nat{v: v}, nil
}

// TryInv attempts to compute the multiplicative inverse of the Nat. It returns an error unless the Nat is 1.
func (n *Nat) TryInv() (*Nat, error) {
	if n.IsOne() {
		return n.Clone(), nil
	}
	return nil, ErrUndefined.WithStackFrame()
}

// IsUnit checks if the Nat is a unit modulo the given NatPlus modulus.
func (n *Nat) IsUnit(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	m, ok := numct.NewModulus(modulus.v)
	if ok == ct.False {
		panic(errs2.New("modulus is not valid"))
	}
	return m.IsUnit(n.v) == ct.True
}

// Cardinal returns the cardinal representation of the Nat.
func (n *Nat) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(n.v))
}

// TryDiv attempts to divide the Nat by another Nat. It returns an error if the division is not exact.
func (n *Nat) TryDiv(other *Nat) (*Nat, error) {
	if _, err := n.isValid(other); err != nil {
		return nil, errs2.Wrap(err)
	}
	v := new(numct.Nat)
	divisorMod, modOk := numct.NewModulus(other.v)
	if modOk != ct.True {
		return nil, errs2.New("failed to create modulus from divisor")
	}
	if ok := v.ExactDiv(n.v, divisorMod); ok != ct.True {
		return nil, ErrInexactDivision.WithStackFrame()
	}
	out := &Nat{v: v}
	return n.isValid(out)
}

// Double returns the Nat doubled.
func (n *Nat) Double() *Nat {
	return n.Add(n)
}

// IsPositive checks if the Nat is positive (greater than 0).
func (n *Nat) IsPositive() bool {
	return !n.IsZero()
}

// Square returns the square of the Nat.
func (n *Nat) Square() *Nat {
	return n.Mul(n)
}

// IsOpIdentity checks if the Nat is the additive identity (0).
func (n *Nat) IsOpIdentity() bool {
	return n.IsZero()
}

// IsBottom checks if the Nat is the bottom element (0).
func (n *Nat) IsBottom() bool {
	return n.v.IsZero() == ct.True
}

// IsZero checks if the Nat is zero.
func (n *Nat) IsZero() bool {
	return n.v.IsZero() == ct.True
}

// IsOne checks if the Nat is one.
func (n *Nat) IsOne() bool {
	return n.v.IsOne() == ct.True
}

// Coprime checks if the Nat is coprime with another Nat.
func (n *Nat) Coprime(other *Nat) bool {
	errs2.Must1(n.isValid(other))
	return n.v.Coprime(other.v) == ct.True
}

// IsProbablyPrime checks if the Nat is probably prime.
func (n *Nat) IsProbablyPrime() bool {
	return n.v.IsProbablyPrime() == ct.True
}

// EuclideanDiv performs Euclidean division of the Nat by another Nat, returning the quotient and remainder.
func (n *Nat) EuclideanDiv(other *Nat) (quot, rem *Nat, err error) {
	errs2.Must1(n.isValid(other))
	vq, vr := new(numct.Nat), new(numct.Nat)
	// Create modulus from divisor
	divisorMod, modOk := numct.NewModulus(other.v)
	if modOk != ct.True {
		return nil, nil, errs2.New("failed to create modulus from divisor")
	}
	if ok := numct.DivModCap(vq, vr, n.v, divisorMod, -1); ok == ct.False {
		return nil, nil, errs2.New("division failed")
	}
	return &Nat{v: vq}, &Nat{v: vr}, nil
}

// EuclideanValuation computes the Euclidean valuation of the Nat.
func (n *Nat) EuclideanValuation() cardinal.Cardinal {
	return cardinal.NewFromSaferith(((*saferith.Nat)(n.Value())))
}

// Mod computes the Nat modulo the given NatPlus modulus.
func (n *Nat) Mod(modulus *NatPlus) *Uint {
	return n.Lift().Mod(modulus)
}

// Sqrt computes the square root of the Nat, returning an error if the square root is not defined.
func (n *Nat) Sqrt() (*Nat, error) {
	v := new(numct.Nat)
	ok := v.Sqrt(n.v)
	if ok == ct.False {
		return nil, ErrUndefined.WithStackFrame()
	}
	return &Nat{v: v}, nil
}

// Compare compares the Nat with another Nat, returning an ordering result.
func (n *Nat) Compare(other *Nat) base.Ordering {
	errs2.Must1(n.isValid(other))
	lt, eq, gt := n.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

// IsLessThanOrEqual checks if the Nat is less than or equal to another Nat.
func (n *Nat) IsLessThanOrEqual(other *Nat) bool {
	errs2.Must1(n.isValid(other))
	lt, eq, _ := n.v.Compare(other.v)
	return lt|eq == ct.True
}

// Lift converts the Nat to an Int.
func (n *Nat) Lift() *Int {
	return &Int{v: n.v.Lift()}
}

// Equal checks if the Nat is equal to another Nat.
func (n *Nat) Equal(other *Nat) bool {
	errs2.Must1(n.isValid(other))
	return n.v.Equal(other.v) == ct.True
}

// Clone creates a copy of the Nat.
func (n *Nat) Clone() *Nat {
	return &Nat{v: n.v.Clone()}
}

// HashCode computes a hash code for the Nat.
func (n *Nat) HashCode() base.HashCode {
	return base.HashCode(n.v.Uint64())
}

// String returns the string representation of the Nat.
func (n *Nat) String() string {
	return n.v.String()
}

// Increment returns the Nat incremented by 1.
func (n *Nat) Increment() *Nat {
	return n.Add(N().One())
}

// Decrement returns the Nat decremented by 1, returning an error if the result would be negative.
func (n *Nat) Decrement() (*Nat, error) {
	return n.TrySub(N().One())
}

// Bytes returns the byte slice representation of the Nat.
func (n *Nat) Bytes() []byte {
	return n.v.Bytes()
}

// BytesBE returns the big-endian byte slice representation of the Nat.
func (n *Nat) BytesBE() []byte {
	return n.Bytes()
}

// Uint64 returns the uint64 representation of the Nat. It wraps around if the Nat is too large.
func (n *Nat) Uint64() uint64 {
	return n.v.Uint64()
}

// Bit returns the value of the i-th bit of the Nat.
func (n *Nat) Bit(i uint) byte {
	return n.v.Bit(i)
}

// Byte returns the value of the i-th byte of the Nat.
func (n *Nat) Byte(i uint) byte {
	return n.v.Byte(i)
}

// IsEven checks if the Nat is even.
func (n *Nat) IsEven() bool {
	return n.v.IsEven() == ct.True
}

// IsOdd checks if the Nat is odd.
func (n *Nat) IsOdd() bool {
	return n.v.IsOdd() == ct.True
}

// Big returns the big.Int representation of the Nat.
func (n *Nat) Big() *big.Int {
	return n.v.Big()
}

// IsTorsionFree checks if the Nat is torsion-free under addition, which is always true for natural numbers.
func (n *Nat) IsTorsionFree() bool {
	return true
}

// ScalarOp performs scalar multiplication of the Nat by another Nat.
func (n *Nat) ScalarOp(sc *Nat) *Nat {
	return n.ScalarMul(sc)
}

// ScalarMul performs scalar multiplication of the Nat by another Nat.
func (n *Nat) ScalarMul(sc *Nat) *Nat {
	return n.Mul(sc)
}

// TrueLen returns the true length of the Nat in bytes.
func (n *Nat) TrueLen() int {
	return n.v.TrueLen()
}

// AnnouncedLen returns the announced length of the Nat in bytes.
func (n *Nat) AnnouncedLen() int {
	return n.v.AnnouncedLen()
}
