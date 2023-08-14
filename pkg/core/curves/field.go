package curves

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
)

type FieldValue = [impl.FieldLimbs]uint64

const (
	FieldBytes     = impl.FieldBytes
	WideFieldBytes = impl.WideFieldBytes
)

type Element interface {
	Value() FieldValue
	Modulus() FieldValue
	Clone() Element
	Cmp(rhs Element) int

	Random(prng io.Reader) Element
	Zero() Element
	One() Element
	IsZero() bool
	IsOne() bool
	IsOdd() bool
	IsEven() bool

	Square() Element
	Double() Element
	Sqrt() Element
	Cube() Element
	Add(rhs Element) Element
	Sub(rhs Element) Element
	Mul(rhs Element) Element
	MulAdd(y, z Element) Element
	Div(rhs Element) Element
	Exp(rhs Element) Element
	Neg() Element

	SetBigInt(value, modulus *big.Int)
	BigInt() *big.Int
	SetBytes(input []byte) (Element, error)
	SetBytesWide(input []byte) (Element, error)
	Bytes() []byte
	FromScalar(sc Scalar) (Element, error)
	Scalar(c Curve) (Element, error)
}
