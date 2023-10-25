package curves

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
)

// the base field of all curves need 4 limbs, but edwards25519 which needs 5.
type FieldValue = []uint64

const (
	FieldBytes     = constants.ScalarBytes
	WideFieldBytes = constants.WideFieldBytes
)

type FieldProfile interface {
	Order() *saferith.Modulus       // p^k
	Characteristic() *saferith.Nat  // p
	ExtensionDegree() *saferith.Nat // k
}

// FieldElement is an element of a finite field \mathbb{F}_{p^k} with p>1 a prime
// and k>1 an integer.
type FieldElement interface {
	// Clone returns a copy of this field element
	Clone() FieldElement

	// Profile returns the profile (p, k and p^k) of the field this element is in
	Profile() FieldProfile
	// Value returns the value of this field element as a slice of uint64s
	Value() FieldValue
	// Modulus returns the modulus of the field this element is in
	Modulus() *saferith.Modulus
	// SubfieldElement returns:
	//  - For k>1 only (subfields Fp1, ...), the element of Fp((i+1)%k) with 0<=i<k.
	//  - For k=1, the element itself regardless of i.
	SubfieldElement(i uint64) FieldElement

	// Random returns a random field element using the reader to retrieve bytes
	Random(prng io.Reader) FieldElement
	// Hash the specific bytes in a manner to yield a
	// uniformly distributed field element
	Hash(x []byte) FieldElement

	// Zero returns the additive identity element
	Zero() FieldElement
	// One returns the multiplicative identity element
	One() FieldElement
	// IsZero returns true if this element is the additive identity element
	IsZero() bool
	// IsOne returns true if this element is the multiplicative identity element
	IsOne() bool
	// IsOdd returns true if this element is odd
	IsOdd() bool
	// IsEven returns true if this element is even
	IsEven() bool
	// Cmp returns:
	//  - -2 if this element is in a different field than rhs
	//  - -1 if this element is less than rhs
	//  - 0 if this element is equal to rhs
	//  - 1 if this element is greater than rhs
	Cmp(rhs FieldElement) int

	// Square returns element*element
	Square() FieldElement
	// Double returns element+element
	Double() FieldElement
	// Sqrt computes the square root of this element if it exists.
	Sqrt() (result FieldElement, wasSquare bool)
	// Cube returns element*element*element
	Cube() FieldElement
	// Add returns element+rhs
	Add(rhs FieldElement) FieldElement
	// Sub returns element-rhs
	Sub(rhs FieldElement) FieldElement
	// Mul returns element*rhs
	Mul(rhs FieldElement) FieldElement
	// MulAdd returns element * y + z mod p
	MulAdd(y, z FieldElement) FieldElement
	// Div returns element*rhs^-1 mod p
	Div(rhs FieldElement) FieldElement
	// Exp returns element^k mod p (i.e. element * element * ... * element) mod p
	Exp(rhs FieldElement) FieldElement
	// Neg returns -element mod p
	Neg() FieldElement

	// New returns an element with the value equal to `value`
	New(v uint64) FieldElement
	// SetNat returns this element set to the value of v
	SetNat(value *saferith.Nat) (FieldElement, error)
	// Nat returns this element as a Nat
	Nat() *saferith.Nat
	// Bytes returns the canonical byte representation of this field element
	Bytes() []byte
	// SetBytes creates a field element from a byte representation
	SetBytes(input []byte) (FieldElement, error)
	// SetBytesWide creates a scalar expecting double the exact number of bytes needed to represent the scalar which is reduced by the modulus
	SetBytesWide(input []byte) (FieldElement, error)
	// FromScalar returns the field element corresponding to the given scalar
	FromScalar(sc Scalar) (FieldElement, error)
	// Scalar casts the field element to a curve scalar
	Scalar(curve Curve) (Scalar, error)
}
