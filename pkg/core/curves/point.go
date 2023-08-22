package curves

import (
	"io"
	"math/big"
)

// Point represents an elliptic curve point.
type Point interface {
	Affine
	Curve() (Curve, error)
	CurveName() string
	Random(prng io.Reader) Point
	Hash(bytes ...[]byte) Point
	Identity() Point
	Generator() Point
	IsIdentity() bool
	IsNegative() bool
	IsOnCurve() bool
	Double() Point
	Scalar() Scalar
	Neg() Point
	ClearCofactor() Point
	Clone() Point
	Add(rhs Point) Point
	Sub(rhs Point) Point
	Mul(rhs Scalar) Point
	Equal(rhs Point) bool
	Set(x, y *big.Int) (Point, error)
	ToAffineCompressed() []byte
	ToAffineUncompressed() []byte
	FromAffineCompressed(bytes []byte) (Point, error)
	FromAffineUncompressed(bytes []byte) (Point, error)
}

type PairingPoint interface {
	Point
	PairingCurve() PairingCurve
	PairingCurveName() string
	OtherGroup() PairingPoint
	Pairing(rhs PairingPoint) Scalar
}

type WeierstrassPoint interface {
	Point
	Projective
}

type Affine interface {
	X() FieldElement
	Y() FieldElement
}

type Projective interface {
	ProjectiveX() FieldElement
	ProjectiveY() FieldElement
	ProjectiveZ() FieldElement
}

type Jacobian interface {
	JacobianX() FieldElement
	JacobianY() FieldElement
	JacobianZ() FieldElement
}

type Extended interface {
	ExtendedX() FieldElement
	ExtendedY() FieldElement
	ExtendedZ() FieldElement
	ExtendedT() FieldElement
}
