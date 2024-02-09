package algebra

import "github.com/cronokirby/saferith"

// AbstractAlgebraicVariety defines some methods that the structure ST must have to be an algebraic variety.
// An algebraic variety is the set of solutions of some polynomial defined over a base field.
// Note that "Abstract" prefix here is due to the conventions of this package. We are not interested in the scheme-theoretic treatment.
// Note that these methods are not sufficient e.g. we are also not defining interface methods related to projective space, even though
// these varieties must have projective embeddings (equivalent to above point).
type AbstractAlgebraicVariety[ST Structure, E, F Element, BaseField EnrichedElement[F]] interface {
	// Dimension returns the number of variables of the polynomial.
	Dimension() int
	// Discriminant returns some number as function of its coefficients. The exact definition is context dependent.
	// eg. for elliptic curves it would be -16(4a^3+27b^2)
	Discriminant() *saferith.Int
	// FrobeniusEndomorphism returns an element whose coordinates are coordinates of p, each raised to the power of characteristic of the basefield.
	FrobeniusEndomorphism(p E) E
	// BaseField returns the base field of the algebraic variety ST.
	BaseField() BaseField
}

// AbstractAlgebraicVarietyElement the type parameter of elements of the algebraic variety ST.
// Note that "Abstract" prefix here is due to the conventions of this package. We are not interested in the scheme-theoretic treatment.
type AbstractAlgebraicVarietyElement[ST Structure, E, F Element] any

// AffineAlgebraicVarietyElementTrait defines additional methods needed to treat affine aspects of algebraic variety members.
type AffineAlgebraicVarietyElementTrait[ST Structure, E, F Element] interface {
	// Affine algebraic variety element has affine coordinates.
	AbstractAffineCoordinates[F]
	// ToAffineCompressed returns the compressed affine serialisation of this element.
	ToAffineCompressed() []byte
	// ToAffineUncompressed returns the uncompressed affine serialisation of this element.
	ToAffineUncompressed() []byte
	// FromAffineCompressed returns the element represented by the compressed affine serialisation.
	FromAffineCompressed(bytes []byte) (E, error)
	// FromAffineUncompressed returns the element represented by the uncompressed affine serialisation.
	FromAffineUncompressed(bytes []byte) (E, error)
}

// AbstractAffineCoordinates defines methods needed for element of an algebraic variety to have affine coordinates.
type AbstractAffineCoordinates[FieldElement Element] interface {
	// AffineCoordinates return an ordered slice of field elements that are the coordinates of the point implementing this interface.
	AffineCoordinates() []FieldElement
}

// AbstractAlgebraicGroup defines methods needed for algebraic variety ST to form a group.
type AbstractAlgebraicGroup[ST Structure, E, F Element, BaseField EnrichedElement[F]] interface {
	// Algebraic group is a group.
	AbstractGroup[ST, E]
	// Algebraic group is an algebraic variety.
	AbstractAlgebraicVariety[ST, E, F, BaseField]
}

// AbstractAlgebraicGroupElement defines methods needed for elements of type E to be elements of algebraic group ST.
type AbstractAlgebraicGroupElement[ST Structure, E, F Element] interface {
	// Algebraic group element is an algebraic variety element.
	AbstractAlgebraicVarietyElement[ST, E, F]
	// Algebraic group element is a group element.
	AbstractGroupElement[ST, E]
}

// AbstractAlgebraicCurve exposes some methods that we need to work with algebraic groups of dimension one easily. ST here is the type of the algebraic curve.
type AbstractAlgebraicCurve[ST Structure, E, F Element, BaseField EnrichedElement[F]] interface {
	// Algebraic curve is an algebraic variety of dimension 1.
	AbstractAlgebraicVariety[ST, E, F, BaseField]
	// NewPoint returns a point of type E given affine coordinates x and y of type F. It returns an error if the (x, y) is not on curve.
	NewPoint(affineX F, affineY F) (E, error)
	// Point returns an unspecified element of the algebraic curve.
	Point() E
}

// AbstractPoint exposes some methods that we need to work with elements of algebraic group ST.
type AbstractPoint[ST Structure, E, F Element] interface {
	// Point has affine coordinates.
	AffineCurveCoordinates[F]
	// Curve returns the algebraic curve containing this element.
	Curve() ST
}

// AffineCurveCoordinates defines methods needed for an algebraic curve's to represent its affine coordinates.
type AffineCurveCoordinates[FieldElement Element] interface {
	// AffineX returns the x coordinate of the point implementing this interface.
	AffineX() FieldElement
	// AffineY returns the y coordinate of the point implementing this interface.
	AffineY() FieldElement
}
