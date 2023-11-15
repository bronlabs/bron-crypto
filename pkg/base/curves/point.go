package curves

import (
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"
)

// Point represents an elliptic curve point.
type Point interface {
	Affine
	// Curve returns the curve that this point belongs to.
	Curve() Curve
	// CurveName returns the name of the curve this point belongs to.
	CurveName() string
	// Random samples a random point from the curve.
	Random(prng io.Reader) (Point, error)
	// Hash hashes the given bytes into a uniformly random point.
	Hash(bytes ...[]byte) (Point, error)
	// Identity returns the identity (I) of the group as a new point.
	Identity() Point
	// Generator returns the generator (G) of the group as a new point.
	Generator() Point
	// IsIdentity returns true if this point is the identity.
	IsIdentity() bool
	// IsNegative returns true if this point is the negative of another point.
	IsNegative() bool
	// IsOnCurve returns true if this point is on its defined curve.
	IsOnCurve() bool
	// Double returns P + P as a new point.
	Double() Point
	// Scalar casts the point to a scalar.
	Scalar() Scalar
	// Neg returns the negative of this point.
	Neg() Point
	// ClearCofactor clears the cofactor of this point, ensuring that it's in the prime-order subgroup.
	ClearCofactor() Point
	// Clone returns a copy of this point.
	Clone() Point
	// Add returns P + Q for this point P and another point Q.
	Add(rhs Point) Point
	// Sub returns P - Q for this point P and another point Q.
	Sub(rhs Point) Point
	// Mul returns kP for this point P and a scalar k.
	Mul(rhs Scalar) Point
	// Equal returns true if this point is equal to another point on the same curve.
	Equal(rhs Point) bool
	// Set overwrites the affine coordinates (X, Y) of this point, treating them as FieldElements.
	Set(x, y *saferith.Nat) (Point, error)
	// ToAffineCompressed returns the compressed affine serialisation of this point.
	ToAffineCompressed() []byte
	// ToAffineUncompressed returns the uncompressed affine serialisation of this point.
	ToAffineUncompressed() []byte
	// FromAffineCompressed returns the point represented by the compressed affine serialisation.
	FromAffineCompressed(bytes []byte) (Point, error)
	// FromAffineUncompressed returns the point represented by the uncompressed affine serialisation.
	FromAffineUncompressed(bytes []byte) (Point, error)
	// IsSmallOrder returns true if this point is in the small-order subgroup.
	IsSmallOrder() bool

	json.Marshaler
	json.Unmarshaler
}

type PairingPoint interface {
	Point
	HashWithDst(input []byte, dst []byte) (PairingPoint, error)
	IsTorsionFree() bool
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
