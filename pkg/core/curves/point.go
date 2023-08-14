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
	X() Element
	Y() Element
}

type Projective interface {
	ProjectiveX() Element
	ProjectiveY() Element
	ProjectiveZ() Element
}

type Jacobian interface {
	JacobianX() Element
	JacobianY() Element
	JacobianZ() Element
}

type Extended interface {
	ExtendedX() Element
	ExtendedY() Element
	ExtendedZ() Element
	ExtendedT() Element
}
