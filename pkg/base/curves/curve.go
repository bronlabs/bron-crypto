package curves

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

const PointAddition algebra.Operator = "Point_Addition"

// GeneralEllipticCurve specifies an Elliptic Curve in the context where scalar multiplication makes sense.
// Specifically, structure ST implements an GeneralEllipticCurve of given type parameters if:
// i. (ST, BaseField, PointAddition) form an algebraic group of dimension 1.
// ii. (ST, PointAddition, ScalarMult) form a module over ScalarRing.
type GeneralEllipticCurve[EllipticCurveType, BaseFieldType, ScalarRingType algebra.Structure, PointType, BaseFieldElementType, ScalarType algebra.Element] interface {
	// Ellitpic curve forms a module over scalar ring.
	algebra.Module[EllipticCurveType, ScalarRingType, PointType, ScalarType]
	// Elliptic curve is an algebraic curve ie. variety of dimension 1.
	algebra.AlgebraicCurve[EllipticCurveType, BaseFieldType, PointType, BaseFieldElementType]
	// Elliptic curve forms an algebraic group over base field.
	algebra.AlgebraicGroup[EllipticCurveType, BaseFieldType, PointType, BaseFieldElementType]
	// Elliptic curve form an additive group with point addition.
	algebra.AdditiveGroup[EllipticCurveType, PointType]
	algebra.FiniteStructure[EllipticCurveType, PointType]

	// TraceOfFrobenius returns the value of q + 1 - N where q is the size of the base field and N is the numbner of points on the curve.
	TraceOfFrobenius() *saferith.Int
	// JInvariant returns the J-invariant of the curve.
	JInvariant() *saferith.Int

	BaseField() BaseField
}

// GeneralEllipticCurvePoint is the interface to represent an element of the ***prime order subgroup*** of an elliptic curve.
type GeneralEllipticCurvePoint[EllipticCurveType, BaseFieldType algebra.Structure, PointType, BaseFieldElementType algebra.Element] interface {
	// Point is an element of an algebraic curve.
	algebra.Point[EllipticCurveType, BaseFieldType, PointType, BaseFieldElementType]
	// Point is an element of an algebraic group element.
	algebra.AlgebraicGroupElement[EllipticCurveType, BaseFieldType, PointType, BaseFieldElementType]
	IsInPrimeSubGroup() bool
	IsNegative() bool
}

// Curve is the interface for the ***prime subgroup*** of an elliptic curve.
// For us, Curve is a cyclic algebraic group of dimension 1 that forms a vector space over the scalar field Zq where q
// is the order of the prime subgroup.
type Curve interface {
	// Curve is an elliptic curve.
	GeneralEllipticCurve[Curve, BaseField, ScalarField, Point, BaseFieldElement, Scalar]
	// Curve forms a one dimensional vector space over the scalar field. It is 1 dimensional vector space,
	// because the group is cyclic.
	algebra.OneDimensionalVectorSpace[Curve, ScalarField, Point, Scalar]
	// Curve is a subgroup of some larger Elliptic curve.
	algebra.SubGroup[Curve, Point]

	Point() Point

	// DeriveFromAffineX accepts the x coordinate and returns (evenY, oddY) coordinates of the resulting points.
	DeriveFromAffineX(x BaseFieldElement) (evenY, oddY Point, err error)

	// HashToFieldElement hashes `msg` using the default curve hasher ([RFC9380])
	// to obtain `count` field elements. Optionally, a custom domain separation
	// tag (dst) can be provided for message expansion (default nil).
	//
	// [RFC9380]: https://datatracker.ietf.org/doc/html/rfc9380#section-5
	HashToFieldElements(count int, msg, optionalDst []byte) (u []BaseFieldElement, err error)
	// HashToScalar hashes `msg` using the default curve hasher ([RFC9380])
	// to obtain `count` scalars (in a prime field Fq). Optionally, a custom domain
	//  separation  tag (dst) can be provided for message expansion (default nil).
	//
	// [RFC9380]: https://datatracker.ietf.org/doc/html/rfc9380#section-5
	HashToScalars(count int, msg, optionalDst []byte) (u []Scalar, err error)
	// HashWithDst hashes `msg` using ([RFC9380]) with a custom DST.
	//
	// [RFC9380]: https://datatracker.ietf.org/doc/html/rfc9380#section-5
	HashWithDst(msg, dst []byte) (Point, error)

	ScalarField() ScalarField
}

// Point is the interface to represent an element of the ***prime order subgroup*** of an elliptic curve.
type Point interface {
	GeneralEllipticCurvePoint[Curve, BaseField, Point, BaseFieldElement]
	// scalar field (ie. field of integers modulo order of the prime subgroup).
	algebra.Vector[Curve, ScalarField, Point, Scalar]
	// Point is element of cyclic group as the subgroup is a prime order.
	algebra.CyclicGroupElement[Curve, Point]
	// Point is element of a group that's subgroup of the larger curve whose order may or may not be prime.
	algebra.SubGroupElement[Curve, Point]

	Curve() Curve
}

// BaseField is the interface for the base field of an elliptic curve.
type BaseField interface {
	algebra.AlgebraicVarietyBaseField[Curve, BaseField, Point, BaseFieldElement]
	// BaseField is equivalent to Zp where elements are of type BaseFieldElement.
	integer.Zp[BaseField, BaseFieldElement]
	// BaseField may be a field extension. eg. BLS12381 G2
	// TODO: At this point we downcast the top level interface to check types of elements of the subfields. Fix later.
	algebra.ExtensionField[BaseField, BaseField, BaseFieldElement, BaseFieldElement]
	// Curve returns the prime order subgroup corresponding to this BaseField.
	Curve() Curve
	BaseFieldElement() BaseFieldElement
}

// BaseFieldElement is the interface for the elements of the base field of an elliptic curve.
type BaseFieldElement interface {
	algebra.AlgebraicVarietyBaseFieldElement[Curve, BaseField, Point, BaseFieldElement]
	// Base field element is equivalent to an element of Zp.
	// TODO: this won't be the case for field extensions
	integer.IntP[BaseField, BaseFieldElement]
	// Base field element may be element of a field extension.
	// TODO: At this point we downcast the top level interface to check types of elements of the subfields. Fix later.
	algebra.ExtensionFieldElement[BaseField, BaseField, BaseFieldElement, BaseFieldElement]
	// BaseField returns the base field containing this element.
	BaseField() BaseField
}

// ScalarField is the interface for the elements of the scalar field of a prime order subgroup of an elliptic curve.
type ScalarField interface {
	// Curve forms a vector space over the scalar field.
	algebra.VectorSpaceBaseField[Curve, ScalarField, Point, Scalar]
	// ScalarField is equivalent to Zp where elements are of type Scalar.
	integer.Zp[ScalarField, Scalar]
	// Curve returns the prime order subgroup corresponding to this ScalarField.
	Curve() Curve
	Scalar() Scalar
}

// Scalar is the interface for the scalars of the prime order subgroup of an elliptic curve.
type Scalar interface {
	// Curve forms a vector space over the scalar field.
	algebra.VectorSpaceScalar[Curve, ScalarField, Point, Scalar]
	// Scalar is equivalent to an element of Zq.
	integer.IntP[ScalarField, Scalar]
	// ScalarField returns the scalar field containing this element.
	ScalarField() ScalarField
}

type ProjectiveCurveCoordinates interface {
	ProjectiveX() BaseFieldElement
	ProjectiveY() BaseFieldElement
	ProjectiveZ() BaseFieldElement
}

type MontgomeryCoordinates interface {
	MontgomeryX() BaseFieldElement
	MontgomeryZ() BaseFieldElement
}

type JacobianCoordinates interface {
	JacobianX() BaseFieldElement
	JacobianY() BaseFieldElement
	JacobianZ() BaseFieldElement
}

type ExtendedCoordinates interface {
	ExtendedX() BaseFieldElement
	ExtendedY() BaseFieldElement
	ExtendedZ() BaseFieldElement
	ExtendedT() BaseFieldElement
}

type PairingCurve interface {
	Name() string
	EmbeddingDegree() *saferith.Nat

	G1() Curve
	G2() Curve
	Gt() Gt

	Pair(pG1, pG2 PairingPoint) (GtMember, error)
	MultiPair(pointsInG1ThenG2 ...PairingPoint) (GtMember, error)
}

type PairingPoint interface {
	Point
	PairingCurve() PairingCurve
	OtherPrimeAlgebraicSubGroup() Curve
	Pair(p PairingPoint) GtMember
}

type Gt interface {
	algebra.Group[Gt, GtMember]
	algebra.MultiplicativeGroup[Gt, GtMember]
}

type GtMember interface {
	algebra.GroupElement[Gt, GtMember]
	algebra.MultiplicativeGroupElement[Gt, GtMember]
	Gt() Gt

	algebra.BytesSerialization[GtMember]
}
