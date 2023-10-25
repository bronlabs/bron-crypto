package curves

import (
	"io"

	"github.com/cronokirby/saferith"
)

// Scalar represents an element of the scalar field \mathbb{F}_q
// of the elliptic curve construction.
type Scalar interface {
	// Curve returns the curve this scalar is associated with
	Curve() Curve
	// CurveName returns the name of the curve this scalar is associated with
	CurveName() string
	// Random returns a random scalar using the provided reader
	// to retrieve bytes
	Random(prng io.Reader) Scalar
	// Hash the specific bytes in a manner to yield a
	// uniformly distributed scalar
	Hash(bytes ...[]byte) Scalar
	// Zero returns the additive identity element
	Zero() Scalar
	// One returns the multiplicative identity element
	One() Scalar
	// IsZero returns true if this element is the additive identity element
	IsZero() bool
	// IsOne returns true if this element is the multiplicative identity element
	IsOne() bool
	// IsOdd returns true if this element is odd
	IsOdd() bool
	// IsEven returns true if this element is even
	IsEven() bool
	// New returns an element with the value equal to `value`
	New(value uint64) Scalar
	// Cmp returns
	// -2 if this element is in a different field than rhs
	// -1 if this element is less than rhs
	// 0 if this element is equal to rhs
	// 1 if this element is greater than rhs
	Cmp(rhs Scalar) int
	// Square returns element*element
	Square() Scalar
	// Double returns element+element
	Double() Scalar
	// Invert returns element^-1 mod p
	Invert() (Scalar, error)
	// Sqrt computes the square root of this element if it exists.
	Sqrt() (Scalar, error)
	// Cube returns element*element*element
	Cube() Scalar
	// Add returns element+rhs
	Add(rhs Scalar) Scalar
	// Sub returns element-rhs
	Sub(rhs Scalar) Scalar
	// Mul returns element*rhs
	Mul(rhs Scalar) Scalar
	// MulAdd returns element * y + z mod p
	MulAdd(y, z Scalar) Scalar
	// Div returns element*rhs^-1 mod p
	Div(rhs Scalar) Scalar
	// Exp returns element^k mod p (i.e. element * element * ... * element) mod p
	Exp(k Scalar) Scalar
	// Neg returns -element mod p
	Neg() Scalar
	// SetNat returns this element set to the value of v
	SetNat(v *saferith.Nat) (Scalar, error)
	// Nat returns this element as a Nat
	Nat() *saferith.Nat
	// Uint64 casts the scalar down to a 64-bit integer. Might overflow.
	Uint64() uint64
	// Bytes returns the canonical byte representation of this scalar
	Bytes() []byte
	// SetBytes creates a scalar from the canonical representation expecting the exact number of bytes needed to represent the scalar
	SetBytes(bytes []byte) (Scalar, error)
	// SetBytesWide creates a scalar expecting double the exact number of bytes needed to represent the scalar which is reduced by the modulus
	SetBytesWide(bytes []byte) (Scalar, error)
	// Clone returns a cloned Scalar of this value
	Clone() Scalar
}

type PairingScalar interface {
	Scalar
	PairingCurve() PairingCurve
	PairingCurveName() string
	SetPoint(p PairingPoint) PairingScalar
	Point() PairingPoint
	OtherGroup() PairingPoint
}
