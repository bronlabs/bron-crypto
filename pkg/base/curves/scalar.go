package curves

import (
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"
)

// Scalar represents an element of the scalar field \mathbb{F}_q, a prime subgroup
// of the multiplicative group of an elliptic curve.
type Scalar[C CurveIdentifier] interface {
	// Clone returns a copy of this scalar.
	Clone() Scalar[C]

	// Curve returns a unified instance of the curve this scalar belongs to.
	Curve() Curve[C]
	// CurveName returns the name of the curve this scalar belongs to.
	CurveName() string
	// Random samples a random Scalar using a uniform bitstring from the reader,
	// and mapping it to a Scalar using SetBytesWide.
	Random(prng io.Reader) (Scalar[C], error)
	// Hash the bytes to yield one uniformly distributed Scalar.
	//
	// Uses the default cipher suite defined in [RFC9380], exanding the input
	// `x` to nElements blocks, and maps each block to a scalar using `SetBytesWide`.
	// Each block is long enough to keep the final bias below
	// the computational security parameter (2^{-128} for 128-bit security).
	//
	// [RFC9380]: https://datatracker.ietf.org/doc/html/rfc9380
	Hash(bytes ...[]byte) (Scalar[C], error)
	// Zero returns an instance of the additive identity element
	Zero() Scalar[C]
	// One returns an instance of the multiplicative identity element.
	One() Scalar[C]
	// IsZero returns true if this element is the additive identity element.
	IsZero() bool
	// IsOne returns true if this element is the multiplicative identity element.
	IsOne() bool
	// IsOdd returns true if this element is odd.
	IsOdd() bool
	// IsEven returns true if this element is even.
	IsEven() bool
	// New returns a scalar with the value equal to `value`.
	New(value uint64) Scalar[C]
	// Cmp returns:
	//  - -2 if this element is in a different field than rhs.
	//  - -1 if this element is less than rhs.
	//  - 0 if this element is equal to rhs.
	//  - 1 if this element is greater than rhs.
	Cmp(rhs Scalar[C]) int
	// Square returns element*element as a new Scalar.
	Square() Scalar[C]
	// Double returns element+element as a new Scalar.
	Double() Scalar[C]
	// Invert returns element^-1 mod q  as a new Scalar.
	Invert() (Scalar[C], error)
	// Sqrt computes the square root of this element as a new Scalar, if it exists.
	Sqrt() (Scalar[C], error)
	// Cube returns element*element*element as a new Scalar.
	Cube() Scalar[C]
	// Add returns `element+rhs mod q` as a new Scalar.
	Add(rhs Scalar[C]) Scalar[C]
	// Sub returns `element-rhs mod q` as a new Scalar.
	Sub(rhs Scalar[C]) Scalar[C]
	// Mul returns `element*rhs mod q` as a new Scalar.
	Mul(rhs Scalar[C]) Scalar[C]
	// MulAdd returns `element * y + z mod q` as a new Scalar.
	MulAdd(y, z Scalar[C]) Scalar[C]
	// Div returns `element*rhs^-1 mod q` as a new Scalar.
	Div(rhs Scalar[C]) Scalar[C]
	// Exp returns `element^k mod q` as a new Scalar.
	Exp(k Scalar[C]) Scalar[C]
	// Neg returns `-element mod q` as a new Scalar.
	Neg() Scalar[C]
	// SetNat returns a new element set to the value of `v mod q`.
	SetNat(v *saferith.Nat) (Scalar[C], error)
	// Nat casts this element as a Nat, without modular reduction.
	Nat() *saferith.Nat
	// Uint64 casts the scalar down to a 64-bit integer. Might overflow.
	Uint64() uint64
	// Bytes returns the canonical big-endian byte representation of this scalar
	// s.t. scalar = Σ_{i=0}^{k-1} (scalar.Bytes()[i] << 8*(k-i-1) ). The result
	// is always FieldBytes long.
	Bytes() []byte
	// SetBytes creates a scalar from a big-endian byte representation
	// s.t. element = Σ_{i=0}^{k-1} (input[i] << 8*(k-i-1) ). The input must be exactly
	// FieldBytes long, and should be in reduced form (less than the modulus q).
	// WARNING: do not use it for uniform sampling, use SetBytesWide instead.
	SetBytes(bytes []byte) (Scalar[C], error)
	// SetBytesWide creates a scalar from uniformly sampled bytes, reducing the result
	// with the subgroup modulus q. The input must be at most k*WideFieldBytes long.
	SetBytesWide(bytes []byte) (Scalar[C], error)

	json.Marshaler
	json.Unmarshaler
}

type PairingScalar[C Curve[C]] interface {
	Scalar[C]
	PairingCurve() PairingCurve[C]
	PairingCurveName() string
	SetPoint(p PairingPoint[C]) PairingScalar[C]
	Point() PairingPoint[C]
	OtherGroup() PairingPoint[C]
}
