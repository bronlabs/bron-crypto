package num

import (
	"io"
	"math/big"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

var (
	nplusInstance *PositiveNaturalNumbers
	nplusOnce     sync.Once
)

// PositiveNaturalNumbers represents the set of positive natural numbers (N\{0}).
type PositiveNaturalNumbers struct{}

// NPlus returns the singleton instance of PositiveNaturalNumbers.
func NPlus() *PositiveNaturalNumbers {
	nplusOnce.Do(func() {
		nplusInstance = &PositiveNaturalNumbers{}
	})
	return nplusInstance
}

// Name returns the name of the structure: "N\{0}".
func (*PositiveNaturalNumbers) Name() string {
	return "N\\{0}"
}

// Characteristic returns the characteristic of PositiveNaturalNumbers, which is 0.
func (*PositiveNaturalNumbers) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

// Order returns the order of PositiveNaturalNumbers, which is infinite.
func (*PositiveNaturalNumbers) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

// One returns the multiplicative identity element of PositiveNaturalNumbers, which is 1.
func (*PositiveNaturalNumbers) One() *NatPlus {
	return &NatPlus{v: numct.NatOne(), m: nil}
}

// FromCardinal creates a NatPlus from the given cardinal, returning an error if the cardinal is zero.
func (*PositiveNaturalNumbers) FromCardinal(c algebra.Cardinal) (*NatPlus, error) {
	if c == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if c.IsZero() {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &NatPlus{v: numct.NewNatFromBytes(c.Bytes()), m: nil}, nil
}

// FromBig creates a NatPlus from the given big.Int, returning an error if the integer is nil or not positive.
func (nps *PositiveNaturalNumbers) FromBig(b *big.Int) (*NatPlus, error) {
	if b == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if b.Sign() <= 0 {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return nps.FromBytes(b.Bytes())
}

// FromModulusCT creates a NatPlus from the given numct.Modulus.
func (*PositiveNaturalNumbers) FromModulusCT(m *numct.Modulus) *NatPlus {
	return &NatPlus{v: m.Nat(), m: m}
}

// FromRat creates a NatPlus from the given Rat, returning an error if the Rat is not a positive integer.
func (nps *PositiveNaturalNumbers) FromRat(v *Rat) (*NatPlus, error) {
	vInt, err := Z().FromRat(v)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return nps.FromInt(vInt)
}

// FromUint64 creates a NatPlus from the given uint64, returning an error if the value is zero.
func (*PositiveNaturalNumbers) FromUint64(value uint64) (*NatPlus, error) {
	if value == 0 {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &NatPlus{v: numct.NewNat(value), m: nil}, nil
}

// FromNat creates a NatPlus from the given Nat, returning an error if the Nat is nil or zero.
func (*PositiveNaturalNumbers) FromNat(value *Nat) (*NatPlus, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value.IsZero() {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &NatPlus{v: value.v.Clone(), m: nil}, nil
}

// FromNatCT creates a NatPlus from the given numct.Nat, returning an error if the value is nil or zero.
func (*PositiveNaturalNumbers) FromNatCT(value *numct.Nat) (*NatPlus, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value.IsZero() == ct.True {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &NatPlus{v: value.Clone(), m: nil}, nil
}

// FromInt creates a NatPlus from the given Int, returning an error if the Int is nil, zero, or negative.
func (*PositiveNaturalNumbers) FromInt(value *Int) (*NatPlus, error) {
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value.IsZero() {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	if value.IsNegative() {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &NatPlus{v: value.Abs().v, m: nil}, nil
}

// FromBytes creates a NatPlus from the given big-endian byte slice, returning an error if the input is empty or represents zero.
func (*PositiveNaturalNumbers) FromBytes(input []byte) (*NatPlus, error) {
	if len(input) == 0 || ct.SliceIsZero(input) == ct.True {
		return nil, ErrIsNil.WithStackFrame()
	}
	out := &NatPlus{v: numct.NewNatFromBytes(input), m: nil}
	if out.v.IsZero() == ct.True {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return out, nil
}

// FromBytesBE creates a NatPlus from the given big-endian byte slice, returning an error if the input is empty or represents zero.
func (nps *PositiveNaturalNumbers) FromBytesBE(input []byte) (*NatPlus, error) {
	out, err := nps.FromBytes(input)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// Random generates a random NatPlus in the range [lowInclusive, highExclusive), returning an error if highExclusive is nil.
func (nps *PositiveNaturalNumbers) Random(lowInclusive, highExclusive *NatPlus, prng io.Reader) (*NatPlus, error) {
	if lowInclusive == nil {
		lowInclusive = nps.Bottom()
	}
	var v numct.Nat
	if err := v.SetRandomRangeLH(lowInclusive.Value(), highExclusive.Value(), prng); err != nil {
		return nil, errs2.Wrap(err)
	}
	return &NatPlus{v: &v, m: nil}, nil
}

// OpIdentity returns the multiplicative identity element of PositiveNaturalNumbers, which is 1.
// Note that this OpIdentity isn't standard, as it considers (N\{0}, *, +) to be a hemi ring, NOT the usual (N\{0}, +, *).
func (nps *PositiveNaturalNumbers) OpIdentity() *NatPlus {
	return nps.One()
}

// ElementSize returns -1 indicating that NatPlus does not have a fixed element size.
func (*PositiveNaturalNumbers) ElementSize() int {
	return -1
}

// Bottom returns the smallest element of PositiveNaturalNumbers, which is 1.
func (nps *PositiveNaturalNumbers) Bottom() *NatPlus {
	return nps.One()
}

// NatPlus represents a positive natural number (N\{0}).
type NatPlus struct {
	v *numct.Nat
	m *numct.Modulus
}

func (*NatPlus) isValid(x *NatPlus) (*NatPlus, error) {
	if x == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if x.v.IsZero() == ct.True {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return x, nil
}

func (np *NatPlus) cacheMont(m *numct.Modulus) *NatPlus {
	var ok ct.Bool
	if np.m == nil {
		if m == nil {
			m, ok = numct.NewModulus(np.v)
			if ok == ct.False {
				panic(errs2.New("modulus is not valid"))
			}
		}
		np.m = m
	}
	return np
}

// Structure returns the algebraic structure of NatPlus, which is PositiveNaturalNumbers.
func (*NatPlus) Structure() algebra.Structure[*NatPlus] {
	return NPlus()
}

// Value returns the underlying numct.Nat value of the NatPlus.
func (np *NatPlus) Value() *numct.Nat {
	if np == nil {
		return nil
	}
	return np.v
}

// Op performs multiplication of two NatPlus elements.
func (np *NatPlus) Op(other *NatPlus) *NatPlus {
	return np.Add(other)
}

// OtherOp performs addition of two NatPlus elements.
func (np *NatPlus) OtherOp(other *NatPlus) *NatPlus {
	return np.Mul(other)
}

// Add performs addition of two NatPlus elements.
func (np *NatPlus) Add(other *NatPlus) *NatPlus {
	errs2.Must1(np.isValid(other))
	v := new(numct.Nat)
	v.Add(np.v, other.v)
	return errs2.Must1(np.isValid(&NatPlus{v: v, m: nil}))
}

// Mul performs multiplication of two NatPlus elements.
func (np *NatPlus) Mul(other *NatPlus) *NatPlus {
	errs2.Must1(np.isValid(other))
	v := new(numct.Nat)
	v.Mul(np.v, other.v)
	out := &NatPlus{v: v, m: nil}
	return errs2.Must1(np.isValid(out))
}

// Lsh performs a left shift operation on the NatPlus.
func (np *NatPlus) Lsh(shift uint) *NatPlus {
	v := new(numct.Nat)
	v.Lsh(np.v, shift)
	out := &NatPlus{v: v, m: nil}
	return errs2.Must1(np.isValid(out))
}

// TryRsh attempts to right shift the NatPlus, returning an error if the result would be zero.
func (np *NatPlus) TryRsh(shift uint) (*NatPlus, error) {
	v := new(numct.Nat)
	v.Rsh(np.v, shift)
	out := &NatPlus{v: v, m: nil}
	return np.isValid(out)
}

// Rsh performs a right shift operation on the NatPlus.
// Panics if the result would be zero.
func (np *NatPlus) Rsh(shift uint) *NatPlus {
	return errs2.Must1(np.TryRsh(shift))
}

// Double returns the result of multiplying the NatPlus by 2.
func (np *NatPlus) Double() *NatPlus {
	return np.Add(np)
}

// Square returns the result of squaring the NatPlus.
func (np *NatPlus) Square() *NatPlus {
	return np.Mul(np)
}

// IsOne checks if the NatPlus is equal to 1.
func (np *NatPlus) IsOne() bool {
	return np.v.IsOne() == ct.True
}

// IsOpIdentity checks if the NatPlus is the multiplicative identity (1).
func (np *NatPlus) IsOpIdentity() bool {
	return np.IsOne()
}

// Compare compares the NatPlus with another NatPlus, returning the ordering result.
func (np *NatPlus) Compare(other *NatPlus) base.Ordering {
	errs2.Must1(np.isValid(other))
	lt, eq, gt := np.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

// TryInv attempts to compute the multiplicative inverse of the NatPlus, returning an error since it does not exist.
func (np *NatPlus) TryInv() (*NatPlus, error) {
	if np.IsOne() {
		return np.Clone(), nil
	}
	return nil, ErrUndefined.WithStackFrame().WithMessage("multiplicative inverse only defined for 1")
}

// TryOpInv attempts to compute the multiplicative inverse of the NatPlus, returning an error since it does not exist.
func (np *NatPlus) TryOpInv() (*NatPlus, error) {
	return np.TryInv()
}

// TryDiv attempts to divide the NatPlus by another NatPlus, returning an error if the division is not exact.
func (np *NatPlus) TryDiv(other *NatPlus) (*NatPlus, error) {
	if _, err := np.isValid(other); err != nil {
		return nil, errs2.Wrap(err)
	}

	var q, r numct.Nat
	if ok := q.Div(&r, np.v, other.v); ok == ct.False {
		return nil, ErrDivisionByZero.WithStackFrame()
	}
	if r.IsNonZero() != ct.False {
		return nil, ErrInexactDivision.WithStackFrame()
	}

	return &NatPlus{v: &q, m: nil}, nil
}

// TrySub attempts to subtract another NatPlus from the NatPlus, returning an error if the result is not a positive natural number.
func (np *NatPlus) TrySub(other *NatPlus) (*NatPlus, error) {
	if _, err := np.isValid(other); err != nil {
		return nil, errs2.Wrap(err)
	}
	if np.IsLessThanOrEqual(other) {
		return nil, ErrOutOfRange.WithStackFrame().WithMessage("result of subtraction is not a positive natural number")
	}
	v := new(numct.Nat)
	v.SubCap(np.v, other.v, -1)
	out := &NatPlus{v: v, m: nil}
	return np.isValid(out)
}

// IsLessThanOrEqual checks if the NatPlus is less than or equal to another NatPlus.
func (np *NatPlus) IsLessThanOrEqual(other *NatPlus) bool {
	errs2.Must1(np.isValid(other))
	lt, eq, _ := np.v.Compare(other.v)
	return lt|eq == ct.True
}

// IsUnit checks if the NatPlus is a unit with respect to the given modulus.
func (np *NatPlus) IsUnit(modulus *NatPlus) bool {
	errs2.Must1(np.isValid(modulus))
	return np.v.Coprime(modulus.v) == ct.True
}

// Equal checks if the NatPlus is equal to another NatPlus.
func (np *NatPlus) Equal(other *NatPlus) bool {
	errs2.Must1(np.isValid(other))
	return np.v.Equal(other.v) == ct.True
}

// Mod computes the modulus of the NatPlus with respect to another NatPlus.
func (np *NatPlus) Mod(modulus *NatPlus) *Uint {
	return np.Lift().Mod(modulus)
}

// Lift converts the NatPlus to an Int.
func (np *NatPlus) Lift() *Int {
	return &Int{v: np.v.Lift()}
}

// Clone creates a copy of the NatPlus.
func (np *NatPlus) Clone() *NatPlus {
	return &NatPlus{v: np.v.Clone(), m: np.m}
}

// HashCode computes the hash code of the NatPlus.
func (np *NatPlus) HashCode() base.HashCode {
	return np.v.HashCode()
}

// Abs returns the absolute value of the NatPlus, which is itself.
func (np *NatPlus) Abs() *NatPlus {
	return np.Clone()
}

// String returns the string representation of the NatPlus.
func (np *NatPlus) String() string {
	return np.v.String()
}

// Increment returns the NatPlus incremented by 1.
func (np *NatPlus) Increment() *NatPlus {
	return np.Add(NPlus().One())
}

// Bytes returns the big-endian byte representation of the NatPlus.
func (np *NatPlus) Bytes() []byte {
	return np.v.Bytes()
}

// BytesBE returns the big-endian byte representation of the NatPlus.
func (np *NatPlus) BytesBE() []byte {
	return np.Bytes()
}

// IsBottom checks if the NatPlus is the smallest element (1).
func (np *NatPlus) IsBottom() bool {
	return np.IsOne()
}

// Bit returns the value of the i-th bit of the NatPlus.
func (np *NatPlus) Bit(i uint) byte {
	return np.v.Bit(i)
}

// Byte returns the value of the i-th byte of the NatPlus.
func (np *NatPlus) Byte(i uint) byte {
	return np.v.Byte(i)
}

// IsEven checks if the NatPlus is even.
func (np *NatPlus) IsEven() bool {
	return np.v.IsEven() == ct.True
}

// IsOdd checks if the NatPlus is odd.
func (np *NatPlus) IsOdd() bool {
	return np.v.IsOdd() == ct.True
}

// Decrement returns the NatPlus decremented by 1, returning an error if the result would be less than 1.
func (np *NatPlus) Decrement() (*NatPlus, error) {
	if np.IsOne() {
		return nil, ErrOutOfRange.WithStackFrame().WithMessage("cannot decrement NatPlus below 1")
	}
	return np.TrySub(NPlus().One())
}

// Big returns the big.Int representation of the NatPlus.
func (np *NatPlus) Big() *big.Int {
	return np.v.Big()
}

func (np *NatPlus) Uint64() uint64 {
	return np.v.Uint64()
}

// Cardinal returns the cardinal representation of the NatPlus.
func (np *NatPlus) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromNumeric(np.v)
}

// Nat returns the Nat representation of the NatPlus.
func (np *NatPlus) Nat() *Nat {
	return &Nat{v: np.v.Clone()}
}

// IsProbablyPrime checks if the NatPlus is probably prime.
func (np *NatPlus) IsProbablyPrime() bool {
	return np.v.IsProbablyPrime() == ct.True
}

// ModulusCT returns the cached modulus or computes it if not cached.
func (np *NatPlus) ModulusCT() *numct.Modulus {
	np.cacheMont(nil)
	return np.m
}

// TrueLen returns the true length of the NatPlus in bytes.
func (np *NatPlus) TrueLen() int {
	return np.v.TrueLen()
}

// AnnouncedLen returns the announced length of the NatPlus in bytes.
func (np *NatPlus) AnnouncedLen() int {
	return np.v.AnnouncedLen()
}
