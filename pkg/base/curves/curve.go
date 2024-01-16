package curves

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

// AbstractEllipticCurve specifies an Elliptic Curve in the context where scalar multiplication makes sense.
// Specifically, structure ST implements an EllipticCurve of given type parameters if:
// i. (ST, BaseField, PointAddition) form an algebraic group of dimension 1.
// ii. (ST, PointAddition, ScalarMult) form a module over ScalarRing.
type AbstractEllipticCurve[ST, BaseFieldType, ScalarRingType algebra.Structure, PointType, BaseFieldElementType, ScalarType algebra.EnrichedElement[ST]] interface {
	// Ellitpic curve forms a module over scalar scalar ring.
	algebra.AbstractModule[ST, PointType, ScalarType, ScalarRingType]
	// Elliptic curve is an algebraic curve ie. variety of dimension 1.
	algebra.AbstractAlgebraicCurve[ST, PointType, BaseFieldElementType, BaseFieldType]
	// Elliptic curve forms an algebraic group over base field.
	algebra.AbstractAlgebraicGroup[ST, PointType, BaseFieldElementType, BaseFieldType]
	// Elliptic curve form an additive group with point addition.
	algebra.AdditiveGroupTrait[ST, PointType]

	// TraceOfFrobenius returns the value of q + 1 - N where q is the size of the base field and N is the numbner of points on the curve.
	TraceOfFrobenius() *saferith.Int
	// JInvariant returns the J-invariant of the curve.
	JInvariant() *saferith.Int
}

// Curve is the interface for the ***prime subgroup*** of an elliptic curve.
// For us, Curve is a cyclic algebraic group of dimension 1 that forms a vector space over the scalar field Zq where q
// is the order of the prime subgroup.
type Curve interface {
	// Curve is an elliptic curve.
	AbstractEllipticCurve[Curve, BaseField, ScalarField, Point, BaseFieldElement, Scalar]
	// Curve forms a one dimensional vector space over the scalar field. It is 1 dimensional vector space,
	// because the group is cyclic.
	algebra.AbstractOneDimensionalVectorSpace[Curve, Point, Scalar, ScalarField]
	// Curve is a subgroup of some larger Elliptic curve.
	algebra.SubGroupTrait

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
}

// BaseField is the interface for the base field of an elliptic curve.
type BaseField interface {
	// BaseField is equivalent to Zp where elements are of type BaseFieldElement.
	algebra.AbstractZp[Curve, BaseFieldElement]
	// BaseField may be a field extension. eg. BLS12381 G2
	// TODO: At this point we downcast the top level interface to check types of elements of the subfields. Fix later.
	algebra.FieldExtensionTrait[Curve, BaseFieldElement, BaseFieldElement]
	// Curve returns the prime order subgroup corresponding to this BaseField.
	Curve() Curve
}

// BaseFieldElement is the interface for the elements of the base field of an elliptic curve.
type BaseFieldElement interface {
	// Base field element is equivalent to an element of Zp.
	algebra.AbstractIntegerFieldElement[Curve, BaseFieldElement]
	// Base field element may be element of a field extension.
	// TODO: At this point we downcast the top level interface to check types of elements of the subfields. Fix later.
	algebra.FieldExtensionElementTrait[BaseFieldElement, BaseFieldElement]
	// BaseField returns the base field containing this element.
	BaseField() BaseField
}

// ScalarField is the interface for the elements of the scalar field of a prime order subgroup of an elliptic curve.
type ScalarField interface {
	// Curve forms a vector space over the scalar field.
	algebra.AbstractVectorSpaceBaseField[Curve, Scalar]
	// ScalarField is equivalent to Zp where elements are of type Scalar.
	algebra.AbstractZp[Curve, Scalar]
	// Curve returns the prime order subgroup corresponding to this ScalarField.
	Curve() Curve
}

// Scalar is the interface for the scalars of the prime order subgroup of an elliptic curve.
type Scalar interface {
	// Curve forms a vector space over the scalar field.
	algebra.AbstractVectorSpaceScalar[Curve, Scalar]
	// Scalar is equivalent to an element of Zq.
	algebra.AbstractIntegerFieldElement[Curve, Scalar]
	// ScalarField returns the scalar field containing this element.
	ScalarField() ScalarField
}

// Point is the interface to represent an element of the ***prime order subgroup*** of an elliptic curve.
type Point interface {
	// Point is an element of an algebraic curve.
	algebra.AbstractPoint[Curve, Point, BaseFieldElement]
	// Point is an element of an algebraic group element.
	algebra.AbstractAlgebraicGroupElement[Curve, Point, BaseFieldElement]
	// Point has affine coordinates.
	algebra.AffineAlgebraicVarietyElementTrait[Curve, Point, BaseFieldElement]
	// Point is an element of the 1 dimensional vector space whose group is the prime order algebraic subgroup and is defined over the
	// scalar field (ie. field of integers modulo order of the prime subgroup).
	algebra.AbstractVector[Curve, Point, Scalar]
	// Point is element of cyclic group as the subgroup is a prime order.
	algebra.AbstractCyclicGroupElement[Curve, Point]
	// Point is an element of an additive group wrt PointAddition operator.
	algebra.AdditiveGroupElementTrait[Curve, Point]
	// Point is element of a group that's subgroup of the larger curve whose order may or may not be prime.
	algebra.SubGroupElementTrait[Curve, Point]
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
