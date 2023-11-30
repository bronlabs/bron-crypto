package curves

import (
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"
)

// Point represents an elliptic curve point.
type Point[C CurveIdentifier] interface {
	Affine[C]
	// Curve returns the curve that this point belongs to.
	Curve() Curve[C]
	// CurveName returns the name of the curve this point belongs to.
	CurveName() string
	// Random samples a random point from the curve.
	Random(prng io.Reader) (Point[C], error)
	// Hash hashes the given bytes into a uniformly random point.
	Hash(bytes ...[]byte) (Point[C], error)
	// Identity returns the identity (I) of the group as a new point.
	Identity() Point[C]
	// Generator returns the generator (G) of the group as a new point.
	Generator() Point[C]
	// IsIdentity returns true if this point is the identity.
	IsIdentity() bool
	// IsNegative returns true if this point is the negative of another point.
	IsNegative() bool
	// IsOnCurve returns true if this point is on its defined curve.
	IsOnCurve() bool
	// Double returns P + P as a new point.
	Double() Point[C]
	// Scalar casts the point to a scalar.
	Scalar() Scalar[C]
	// Neg returns the negative of this point.
	Neg() Point[C]
	// ClearCofactor clears the cofactor of this point, ensuring that it's in the prime-order subgroup.
	ClearCofactor() Point[C]
	// Clone returns a copy of this point.
	Clone() Point[C]
	// Add returns P + Q for this point P and another point Q.
	Add(rhs Point[C]) Point[C]
	// Sub returns P - Q for this point P and another point Q.
	Sub(rhs Point[C]) Point[C]
	// Mul returns kP for this point P and a scalar k.
	Mul(rhs Scalar[C]) Point[C]
	// Equal returns true if this point is equal to another point on the same curve.
	Equal(rhs Point[C]) bool
	// Set overwrites the affine coordinates (X, Y) of this point, treating them as FieldElements.
	Set(x, y *saferith.Nat) (Point[C], error)
	// ToAffineCompressed returns the compressed affine serialisation of this point.
	ToAffineCompressed() []byte
	// ToAffineUncompressed returns the uncompressed affine serialisation of this point.
	ToAffineUncompressed() []byte
	// FromAffineCompressed returns the point represented by the compressed affine serialisation.
	FromAffineCompressed(bytes []byte) (Point[C], error)
	// FromAffineUncompressed returns the point represented by the uncompressed affine serialisation.
	FromAffineUncompressed(bytes []byte) (Point[C], error)
	// IsSmallOrder returns true if this point is in the small-order subgroup.
	IsSmallOrder() bool

	json.Marshaler
	json.Unmarshaler
}

type PairingPoint[C CurveIdentifier] interface {
	Point[C]
	HashWithDst(input []byte, dst []byte) (PairingPoint[C], error)
	IsTorsionFree() bool
	PairingCurve() PairingCurve[C]
	PairingCurveName() string
	OtherGroup() PairingPoint[C]
	Pairing(rhs PairingPoint[C]) Scalar[C]
}

type WeierstrassPoint[C CurveIdentifier] interface {
	Point[C]
	Projective[C]
}

type Affine[C CurveIdentifier] interface {
	X() FieldElement[C]
	Y() FieldElement[C]
}

type Projective[C CurveIdentifier] interface {
	ProjectiveX() FieldElement[C]
	ProjectiveY() FieldElement[C]
	ProjectiveZ() FieldElement[C]
}

type Jacobian[C CurveIdentifier] interface {
	JacobianX() FieldElement[C]
	JacobianY() FieldElement[C]
	JacobianZ() FieldElement[C]
}

type Extended[C Curve[C]] interface {
	ExtendedX() FieldElement[C]
	ExtendedY() FieldElement[C]
	ExtendedZ() FieldElement[C]
	ExtendedT() FieldElement[C]
}
