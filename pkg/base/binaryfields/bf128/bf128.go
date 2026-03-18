package bf128

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	// Name is the human-readable identifier for this field: GF(2^128).
	Name = "F_{2^128}"

	// FieldElementSize is the byte length of a serialised field element (128 bits = 16 bytes).
	FieldElementSize = 16

	// FieldElementLimbs is the number of uint64 limbs used to represent a field element internally.
	FieldElementLimbs = 2
)

var (
	instance = &Field{}

	_ algebra.FieldExtension[*FieldElement]        = (*Field)(nil)
	_ algebra.FiniteField[*FieldElement]           = (*Field)(nil)
	_ algebra.FieldExtensionElement[*FieldElement] = (*FieldElement)(nil)
	_ algebra.FiniteFieldElement[*FieldElement]    = (*FieldElement)(nil)
)

// Field represents the binary extension field GF(2^128), constructed as
// GF(2)[X] / (X^128 + X^7 + X^2 + X + 1). The irreducible polynomial is
// from Table A.1 of "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone).
//
// The additive group is (GF(2^128), XOR) with identity 0. The multiplicative
// group is (GF(2^128)*, carry-less multiplication) with identity 1 and order 2^128 − 1.
// The field has characteristic 2, so negation and subtraction are both XOR (identical to addition).
type Field struct{}

// NewField returns the singleton GF(2^128) field instance.
func NewField() *Field {
	return instance
}

// Random samples a uniformly random field element from the provided PRNG.
func (f *Field) Random(prng io.Reader) (*FieldElement, error) {
	var data [16]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to read random bytes")
	}
	return f.FromBytes(data[:])
}

// RandomNonZero samples a uniformly random non-zero field element. It resamples
// on the negligible chance of drawing zero.
func (f *Field) RandomNonZero(prng io.Reader) (*FieldElement, error) {
	e, err := f.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random element")
	}
	for e.IsZero() {
		e, err = f.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to generate random element")
		}
	}
	return e, nil
}

// Hash deterministically maps arbitrary data to a field element using BLAKE2b-128.
func (f *Field) Hash(data []byte) (*FieldElement, error) {
	h, err := blake2b.New(FieldElementSize, nil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create hasher")
	}
	_, err = h.Write(data)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to write to hasher")
	}
	return f.FromBytes(h.Sum(nil))
}

// Name returns the human-readable field identifier "F_{2^128}".
func (*Field) Name() string {
	return Name
}

// Order returns the field order 2^128 as a cardinal.
func (*Field) Order() cardinal.Cardinal {
	orderBig := new(big.Int)
	orderBig.SetBit(orderBig, 128, 1)
	return cardinal.NewFromBig(orderBig)
}

// ElementSize returns the byte length of a serialised field element (16 bytes).
func (*Field) ElementSize() int {
	return FieldElementSize
}

// Characteristic returns the field characteristic 2.
func (*Field) Characteristic() cardinal.Cardinal {
	return cardinal.New(2)
}

// OpIdentity returns the additive identity (zero).
func (f *Field) OpIdentity() *FieldElement {
	return f.Zero()
}

// One returns the multiplicative identity element.
func (*Field) One() *FieldElement {
	return &FieldElement{1, 0}
}

// Zero returns the additive identity element.
func (*Field) Zero() *FieldElement {
	return &FieldElement{0, 0}
}

// IsDomain reports whether this ring is an integral domain. GF(2^128) is a field,
// so it is trivially a domain.
func (*Field) IsDomain() bool {
	return true
}

// ExtensionDegree returns the degree of the field extension over GF(2), which is 128.
func (*Field) ExtensionDegree() uint {
	return 128
}

// FromComponentsBytes reconstructs a field element from 128 big-endian bit
// components over GF(2). Each of the 128 entries must be a single byte with
// value 0 or 1. Component 0 is the coefficient of X^127 (MSB) and component 127
// is the coefficient of X^0 (LSB).
func (*Field) FromComponentsBytes(data [][]byte) (*FieldElement, error) {
	if len(data) != 128 {
		return nil, ErrInvalidLength.WithMessage("invalid number of components for F2e128 element (is %d, should be 128)", len(data))
	}
	el := &FieldElement{}
	for i := range 128 {
		if len(data[i]) != 1 {
			return nil, ErrInvalidLength.WithMessage("component %d has invalid length %d (should be 1)", i, len(data[i]))
		}
		if data[i][0] > 1 {
			return nil, ErrInvalidLength.WithMessage("component %d has invalid value %d (should be 0 or 1)", i, data[i][0])
		}
		bitPos := 127 - i
		el[bitPos/64] |= uint64(data[i][0]) << (bitPos % 64)
	}
	return el, nil
}

// FromBytes deserialises a field element from exactly 16 big-endian bytes.
func (*Field) FromBytes(buf []byte) (*FieldElement, error) {
	el := &FieldElement{}
	if len(buf) != FieldElementSize {
		return nil, ErrInvalidLength.WithMessage("invalid length of bytes for F2e128 element (is %d, should be %d)", len(buf), 16)
	}
	el[0] = binary.BigEndian.Uint64(buf[8:16])
	el[1] = binary.BigEndian.Uint64(buf[:8])
	return el, nil
}

// Select returns x if choice is 1, or y if choice is 0, in constant time.
func (*Field) Select(choice uint64, x, y *FieldElement) *FieldElement {
	zSlice := ct.CSelectInts(ct.Choice(choice), x[:], y[:])
	return &FieldElement{
		zSlice[0],
		zSlice[1],
	}
}

// FieldElement represents an element of GF(2^128). Internally stored as two
// uint64 limbs in little-endian limb order: el[0] holds bits 0–63 and el[1]
// holds bits 64–127, where bit i is the coefficient of X^i in the polynomial
// representation modulo X^128 + X^7 + X^2 + X + 1.
type FieldElement [2]uint64

// Structure returns the parent GF(2^128) field.
func (*FieldElement) Structure() algebra.Structure[*FieldElement] {
	return NewField()
}

// Clone returns a deep copy of the field element.
func (el *FieldElement) Clone() *FieldElement {
	var clone FieldElement
	copy(clone[:], el[:])
	return &clone
}

// HashCode returns a non-cryptographic hash for use in hash-based collections.
func (el *FieldElement) HashCode() base.HashCode {
	return base.HashCode(el[0] ^ el[1])
}

// String returns a human-readable hexadecimal representation of the element.
func (el *FieldElement) String() string {
	return fmt.Sprintf("F2e128(%016x%016x)", el[1], el[0])
}

// Op performs the additive group operation (XOR), which is the primary group
// operation for the additive group of GF(2^128).
func (el *FieldElement) Op(e *FieldElement) *FieldElement {
	return el.Add(e)
}

// OtherOp performs the multiplicative group operation (carry-less multiplication
// modulo the irreducible polynomial).
func (el *FieldElement) OtherOp(e *FieldElement) *FieldElement {
	return el.Mul(e)
}

// Double returns 2·el. In characteristic 2, every element doubled is zero.
func (*FieldElement) Double() *FieldElement {
	return NewField().Zero()
}

// Square returns el^2 in GF(2^128).
func (el *FieldElement) Square() *FieldElement {
	return el.Mul(el)
}

// IsOpIdentity reports whether el is the additive identity (zero).
func (el *FieldElement) IsOpIdentity() bool {
	return el.IsZero()
}

// TryOpInv returns the additive inverse of el. In characteristic 2, every element
// is its own additive inverse (negation is the identity function), so this always succeeds.
func (el *FieldElement) TryOpInv() (*FieldElement, error) {
	x := el.Neg()
	return x, nil
}

// IsOne reports whether el is the multiplicative identity.
func (el *FieldElement) IsOne() bool {
	return (el[1] | (el[0] ^ 1)) == 0
}

// TryInv computes the multiplicative inverse of el in GF(2^128) using the
// extended Euclidean algorithm for binary polynomials. Returns an error if
// el is zero.
func (el *FieldElement) TryInv() (*FieldElement, error) {
	if el.IsZero() {
		return nil, ErrDivisionByZero
	}
	if el.IsOne() {
		return NewField().One(), nil
	}

	b := NewField().Zero()
	c := NewField().One()
	// u starts as the irreducible polynomial X^128 + X^7 + X^2 + X + 1 reduced
	// to its low 128 bits (X^128 is implicit in the modular representation).
	u := &FieldElement{(1 << 7) | (1 << 2) | (1 << 1) | (1 << 0), 0}
	v := el.Clone()
	j := 128 - v.degree()
	u = u.Sub(v.shiftLeft(j))
	b = b.Sub(c.shiftLeft(j))

	for u.degree() > 0 {
		if u.degree() < v.degree() {
			u, v = v, u
			b, c = c, b
		}
		j = u.degree() - v.degree()
		u = u.Sub(v.shiftLeft(j))
		b = b.Sub(c.shiftLeft(j))
	}

	return b, nil
}

// TryDiv computes el / e in GF(2^128) by multiplying el by the inverse of e.
// Returns an error if e is zero.
func (el *FieldElement) TryDiv(e *FieldElement) (*FieldElement, error) {
	eInv, err := e.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert element")
	}
	return el.Mul(eInv), nil
}

// IsZero reports whether el is the additive identity (all bits zero).
func (el *FieldElement) IsZero() bool {
	return (el[1] | el[0]) == 0
}

// TryNeg returns the additive inverse. In characteristic 2, negation is the
// identity: -a = a for all a.
func (el *FieldElement) TryNeg() (*FieldElement, error) {
	return el.Neg(), nil
}

// TrySub returns el - e. In characteristic 2, subtraction equals addition (XOR).
func (el *FieldElement) TrySub(e *FieldElement) (*FieldElement, error) {
	return el.Sub(e), nil
}

// OpInv returns the additive inverse. In characteristic 2, -a = a for all a.
func (el *FieldElement) OpInv() *FieldElement {
	return el.Neg()
}

// Neg returns the additive inverse. In characteristic 2, every element is its
// own negation, so this returns a clone of el.
func (el *FieldElement) Neg() *FieldElement {
	return el.Clone()
}

// Sub returns el - e. In characteristic 2, subtraction is identical to addition (XOR).
func (el *FieldElement) Sub(e *FieldElement) *FieldElement {
	return el.Add(e)
}

// IsProbablyPrime reports whether el is probably prime as a natural number.
// Field elements are not natural numbers; this always returns false.
func (*FieldElement) IsProbablyPrime() bool {
	return false
}

// EuclideanDiv performs Euclidean division in a field: el / rhs with zero remainder.
// Returns an error if rhs is zero.
func (el *FieldElement) EuclideanDiv(rhs *FieldElement) (quot, rem *FieldElement, err error) {
	quot, err = el.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("division by zero")
	}
	return quot, NewField().Zero(), nil
}

// EuclideanValuation returns the Euclidean valuation: 0 for the zero element,
// 1 for all non-zero elements (since every non-zero field element is a unit).
func (el *FieldElement) EuclideanValuation() cardinal.Cardinal {
	if el.IsZero() {
		return cardinal.New(0)
	} else {
		return cardinal.New(1)
	}
}

// ComponentsBytes returns the 128 coefficients of the polynomial representation
// over GF(2) in big-endian order. Each entry is a single byte, either 0 or 1.
// Component 0 is the coefficient of X^127 (MSB) and component 127 is the
// coefficient of X^0 (LSB).
func (el *FieldElement) ComponentsBytes() [][]byte {
	out := make([][]byte, 128)
	for i := range 128 {
		bitPos := 127 - i
		out[i] = []byte{byte(el[bitPos/64] >> (bitPos % 64) & 1)}
	}
	return out
}

// Add returns el + e. Addition in GF(2^128) is bitwise XOR.
func (el *FieldElement) Add(y *FieldElement) *FieldElement {
	return &FieldElement{el[0] ^ y[0], el[1] ^ y[1]}
}

// Mul returns el * e in GF(2^128) using carry-less (polynomial) multiplication
// followed by reduction modulo f(X) = X^128 + X^7 + X^2 + X + 1.
// The algorithm is the shift-and-XOR method from Section 2.3 of
// "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone),
// with stacked modular reduction from Algorithm 2.40 / Figure 2.9.
func (el *FieldElement) Mul(rhs *FieldElement) *FieldElement {
	var z [4]uint64
	var b = [3]uint64{rhs[0], rhs[1], 0}
	for k := range 64 {
		for j := range FieldElementLimbs {
			// conditionally add a copy of shifted B to C, depending on the appropriate bit of A
			mask := -(el[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFF... else 0x000...
			for i := range FieldElementLimbs + 1 {
				z[j+i] ^= b[i] & mask
			}
		}
		for i := FieldElementLimbs; i > 0; i-- {
			b[i] = b[i]<<1 | b[i-1]>>63
		}
		b[0] <<= 1
	}
	// Modular reduction (stacked precomputation of Algorithm 2.40 in t, see Figure 2.9)
	for i := 2*FieldElementLimbs - 1; i >= FieldElementLimbs; i-- {
		z[i-2] ^= z[i] << 7
		z[i-1] ^= z[i] >> 57
		z[i-2] ^= z[i] << 2
		z[i-1] ^= z[i] >> 62
		z[i-2] ^= z[i] << 1
		z[i-1] ^= z[i] >> 63
		z[i-2] ^= z[i]
	}

	return (*FieldElement)(&[FieldElementLimbs]uint64{z[0], z[1]})
}

// Bytes serialises the field element as 16 big-endian bytes.
func (el *FieldElement) Bytes() []byte {
	buf := make([]byte, FieldElementSize)
	binary.BigEndian.PutUint64(buf[:8], el[1])
	binary.BigEndian.PutUint64(buf[8:16], el[0])
	return buf
}

// Equal reports whether el and rhs represent the same field element, in constant time.
func (el *FieldElement) Equal(rhs *FieldElement) bool {
	return ((el[0] ^ rhs[0]) | (el[1] ^ rhs[1])) == 0
}

// shiftLeft returns el * X^k, i.e. a left shift of the polynomial by k positions.
// Bits shifted beyond position 127 are discarded (no modular reduction).
func (el *FieldElement) shiftLeft(k int) *FieldElement {
	if k <= 0 {
		return el.Clone()
	}
	if k >= 128 {
		return &FieldElement{0, 0}
	}
	if k >= 64 {
		return &FieldElement{0, el[0] << (k - 64)}
	}
	return &FieldElement{el[0] << k, (el[1] << k) | (el[0] >> (64 - k))}
}

// degree returns the degree of el when viewed as a polynomial over GF(2).
// Returns -1 for the zero polynomial and 0..127 for non-zero elements.
func (el *FieldElement) degree() int {
	z := bits.LeadingZeros64(el[1])
	if z == 64 {
		z += bits.LeadingZeros64(el[0])
	}
	return 127 - z // -1 for the zero polynomial, 0..127 for nonzero
}

var (
	// ErrDivisionByZero is returned when attempting to invert or divide by the zero element.
	ErrDivisionByZero = errs.New("division by zero")

	// ErrInvalidLength is returned when byte slice inputs have incorrect length.
	ErrInvalidLength = errs.New("invalid length")
)
