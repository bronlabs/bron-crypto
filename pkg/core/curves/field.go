package curves

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
)

// the base field of all curves need 4 limbs, but edwards25519 which needs 5.
type FieldValue = []uint64

const (
	FieldBytes     = impl.FieldBytes
	WideFieldBytes = impl.WideFieldBytes
)

type FieldProfile interface {
	Order() *big.Int           // p^k
	Characteristic() *big.Int  // p
	ExtensionDegree() *big.Int // k
}

type FieldElement interface {
	Profile() FieldProfile
	Value() FieldValue
	Modulus() *big.Int
	Clone() FieldElement
	Cmp(rhs FieldElement) int

	New(v int) FieldElement
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

	SetBigInt(value *big.Int) (FieldElement, error)
	BigInt() *big.Int
	SetBytes(input []byte) (FieldElement, error)
	SetBytesWide(input []byte) (FieldElement, error)
	Bytes() []byte
	FromScalar(sc Scalar) (FieldElement, error)
	Scalar(curve Curve) (Scalar, error)
}
