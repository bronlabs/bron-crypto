package curves

import (
	"io"

	"github.com/cronokirby/saferith"
)

// the base field of most curves uses an arithmetic representation with 4 limbs
// (mod 2^64). edwards25519 is the exception with 5 limbs (mod 2^51).
type FieldValue = []uint64

type FieldProfile interface {
	Order() *saferith.Modulus       // p^k
	Characteristic() *saferith.Nat  // p
	ExtensionDegree() *saferith.Nat // k
	FieldBytes() int                // Number of bytes required to represent a FieldElement, required for `SetBytes()`
	WideFieldBytes() int            // Number of bytes required to map uniformly to a FieldElement, required for `SetBytesWide()`
}

// FieldElement is an element of a finite field \mathbb{F}_{p^k} with p>1 a prime
// and k>=1 an integer, with k=1 in most cases (prime field \mathbb{F}_p).
type FieldElement interface {
	// Clone returns a copy of this field element.
	Clone() FieldElement

	// Profile returns the profile (p, k and p^k) of the field this element is in.
	Profile() FieldProfile
	// Value returns the limbs of this field element, defined over bit intervals
	// of the numerical range of the field. Most prime fields have 4 limbs (each
	// covering 64 bits of prime modulus), except for edwards25519 which has 5
	// limbs (each covering 51 bits).
	Value() FieldValue
	// Modulus returns the modulus of the field this element is in
	Modulus() *saferith.Modulus
	// SubfieldElement returns a field element in F_p, a subfield of F_{p^k} depending on its extension degree k:
	//  - For k>1 (with subfields F_{p_1}, ..., F_{p_k}), the element of F_{p_((i+1)%k)}.
	//  - For k=1, the element itself (in F_p already) regardless of i.
	SubfieldElement(i uint64) FieldElement

	// Random samples a random field element using a uniform bitstring from the
	// reader, and mapping it to a field element using SetBytesWide.
	Random(prng io.Reader) (FieldElement, error)
	// Hash the bytes to yield nElements uniformly distributed field elements.
	//
	// Uses the default cipher suite defined in RFC9380 (in hashing/hash2curve package),
	// exanding the input `x` to nElements blocks, and maps each block to a field
	// element using SetBytesWide. Each block is long enough to keep the final
	// bias below the computational security parameter (2^{-128} for 128-bit security).
	Hash(x []byte) (FieldElement, error)

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

	// Square returns element*element in a new FieldElement
	Square() FieldElement
	// Double returns element+element in a new FieldElement
	Double() FieldElement
	// Sqrt computes the square root of this element in a new FieldElement if it exists.
	Sqrt() (result FieldElement, wasSquare bool)
	// Cube returns element*element*element in a new FieldElement
	Cube() FieldElement
	// Add returns element+rhs in a new FieldElement
	Add(rhs FieldElement) FieldElement
	// Sub returns element-rhs in a new FieldElement
	Sub(rhs FieldElement) FieldElement
	// Mul returns element*rhs in a new FieldElement
	Mul(rhs FieldElement) FieldElement
	// MulAdd returns element * y + z in a new FieldElement
	MulAdd(y, z FieldElement) FieldElement
	// Div returns element*rhs^-1 in a new FieldElement
	Div(rhs FieldElement) FieldElement
	// Exp returns element^k in a new FieldElement
	Exp(rhs FieldElement) FieldElement
	// Neg returns (-element) in a new FieldElement
	Neg() FieldElement

	// New returns an element with the value set to `v`
	New(v uint64) FieldElement
	// SetNat returns this element set to the value of v
	SetNat(value *saferith.Nat) (FieldElement, error)
	// Nat returns this element as a Nat
	Nat() *saferith.Nat
	// Bytes returns the canonical little-endian byte representation of this field
	// element s.t. element = Σ_{i=0}^{k-1} (element.Bytes()[i] << 8*i). The
	// result is always k*FieldBytes long.
	Bytes() []byte
	// SetBytes creates a new field element from a little-endian byte representation
	// s.t. element = Σ_{i=0}^{k-1} (input[i] << 8*i). The input must be exactly
	// k*FieldBytes long, and must be less than the modulus.
	// WARNING: do not use it for uniform sampling, use SetBytesWide instead.
	SetBytes(input []byte) (FieldElement, error)
	// SetBytesWide creates a new field element from uniformly sampled bytes, reducing
	// the result with the field modulus. The input must be at most k*WideFieldBytes long.
	SetBytesWide(input []byte) (FieldElement, error)
	// FromScalar casts a scalar to its corresponding field element, without reduction.
	FromScalar(sc Scalar) (FieldElement, error)
	// Scalar casts the field element to a curve scalar, reducing its value mod
	// the prime subgroup order.
	Scalar(curve Curve) (Scalar, error)
}
