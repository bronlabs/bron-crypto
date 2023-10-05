package curves

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
)

// the base field of all curves need 4 limbs, but edwards25519 which needs 5.
type FieldValue = []uint64

const (
	FieldBytes     = constants.ScalarBytes
	WideFieldBytes = impl.WideFieldBytes
)

type FieldProfile interface {
	Order() *saferith.Modulus       // p^k
	Characteristic() *saferith.Nat  // p
	ExtensionDegree() *saferith.Nat // k
}

type FieldElement interface {
	Profile() FieldProfile
	Value() FieldValue
	Modulus() *saferith.Modulus
	Clone() FieldElement
	Cmp(rhs FieldElement) int

	New(v uint64) FieldElement
	Random(prng io.Reader) FieldElement
	Hash(x []byte) FieldElement
	Zero() FieldElement
	One() FieldElement
	IsZero() bool
	IsOne() bool
	IsOdd() bool
	IsEven() bool

	Square() FieldElement
	Double() FieldElement
	Sqrt() (result FieldElement, wasSquare bool)
	Cube() FieldElement
	Add(rhs FieldElement) FieldElement
	Sub(rhs FieldElement) FieldElement
	Mul(rhs FieldElement) FieldElement
	MulAdd(y, z FieldElement) FieldElement
	Div(rhs FieldElement) FieldElement
	Exp(rhs FieldElement) FieldElement
	Neg() FieldElement

	SetNat(value *saferith.Nat) (FieldElement, error)
	Nat() *saferith.Nat
	SetBytes(input []byte) (FieldElement, error)
	SetBytesWide(input []byte) (FieldElement, error)
	Bytes() []byte
	FromScalar(sc Scalar) (FieldElement, error)
	Scalar(curve Curve) (Scalar, error)
}
