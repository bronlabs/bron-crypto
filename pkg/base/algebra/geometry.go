package algebra

import "github.com/cronokirby/saferith"

// AlgebraicVariety defines some methods that the structure ST must have to be an algebraic variety.
// An algebraic variety is the set of solutions of some polynomial defined over a base field.
// Note that these methods are not sufficient eg. we are also not defining interface methods related to projective space, even though
// these varieties must have projective embeddings (equivalent to above point).
type AlgebraicVariety[VarietyType, BaseFieldType Structure, VarietyElementType, BaseFieldElementType Element] interface {
	// Dimension returns the number of variables of the polynomial.
	Dimension() int
	// Discriminant returns some number as function of its coefficients. The exact definition is context dependent.
	// eg. for elliptic curves it would be -16(4a^3+27b^2)
	Discriminant() *saferith.Int
	// FrobeniusEndomorphism returns an element whose coordinates are coordinates of p, each raised to the power of characteristic of the base field.
	FrobeniusEndomorphism(p VarietyElementType) VarietyElementType
	// BaseField returns the base field of the algebraic variety ST.
	AlgebraicVarietyBaseField() AlgebraicVarietyBaseField[VarietyType, BaseFieldType, VarietyElementType, BaseFieldElementType]
}

// AlgebraicVarietyElement the type parameter of elements of the algebraic variety ST.
type AlgebraicVarietyElement[VarietyType, BaseFieldType Structure, VarietyElementType, BaseFieldElementType Element] any

type AlgebraicVarietyBaseField[VarietyType, BaseFieldType Structure, VarietyElementType, BaseFieldElementType Element] interface {
	Field[BaseFieldType, BaseFieldElementType]
	AlgebraicVariety() AlgebraicVariety[VarietyType, BaseFieldType, VarietyElementType, BaseFieldElementType]
}

type AlgebraicVarietyBaseFieldElement[VarietyType, BaseFieldType Structure, VarietyElementType, BaseFieldElementType Element] interface {
	FieldElement[BaseFieldType, BaseFieldElementType]
}

// AffineAlgebraicVarietyElement defines additional methods needed to treat affine aspects of algebraic variety members.
type AffineAlgebraicVarietyElement[VarietyType, BaseFieldType Structure, VarietyElementType, BaseFieldElementType Element] interface {
	AlgebraicVarietyElement[VarietyType, BaseFieldType, VarietyElementType, BaseFieldElementType]
	// AffineCoordinates return an ordered slice of field elements that are the coordinates of the point implementing this interface.
	AffineCoordinates() []BaseFieldElementType
	// ToAffineCompressed returns the compressed affine serialisation of this element.
	ToAffineCompressed() []byte
	// ToAffineUncompressed returns the uncompressed affine serialisation of this element.
	ToAffineUncompressed() []byte
	// FromAffineCompressed returns the element represented by the compressed affine serialisation.
	FromAffineCompressed(bytes []byte) (VarietyElementType, error)
	// FromAffineUncompressed returns the element represented by the uncompressed affine serialisation.
	FromAffineUncompressed(bytes []byte) (VarietyElementType, error)
}

// AlgebraicGroup defines methods needed for algebraic variety ST to form a group.
type AlgebraicGroup[GroupType, BaseFieldType Structure, GroupElementType, BaseFieldElementType Element] interface {
	// Algebraic group is a group.
	Group[GroupType, GroupElementType]
	// Algebraic group is an algebraic variety.
	AlgebraicVariety[GroupType, BaseFieldType, GroupElementType, BaseFieldElementType]
}

// AlgebraicGroupElement defines methods needed for elements of type E to be elements of algebraic group ST.
type AlgebraicGroupElement[GroupType, BaseFieldType Structure, GroupElementType, BaseFieldElementType Element] interface {
	// Algebraic group element is an algebraic variety element.
	AlgebraicVarietyElement[GroupType, BaseFieldType, GroupElementType, BaseFieldElementType]
	// Algebraic group element is a group element.
	GroupElement[GroupType, GroupElementType]
}

// AlgebraicCurve exposes some methods that we need to work with algebraic groups of dimension one easily. ST here is the type of the algebraic curve.
type AlgebraicCurve[CurveType, BaseFieldType Structure, PointType, BaseFieldElementType Element] interface {
	// Algebraic curve is an algebraic variety of dimension 1.
	AlgebraicVariety[CurveType, BaseFieldType, PointType, BaseFieldElementType]
	// NewPoint returns a point of type E given affine coordinates x and y of type F. It returns an error if the (x, y) is not on curve.
	NewPoint(affineX, affineY AlgebraicVarietyBaseFieldElement[CurveType, BaseFieldType, PointType, BaseFieldElementType]) (PointType, error)
}

// Point exposes some methods that we need to work with elements of algebraic group ST.
type Point[CurveType, BaseFieldType Structure, PointType, BaseFieldElementType Element] interface {
	AffineAlgebraicVarietyElement[CurveType, BaseFieldType, PointType, BaseFieldElementType]
	// AffineX returns the x coordinate of the point implementing this interface.
	AffineX() BaseFieldElementType
	// AffineY returns the y coordinate of the point implementing this interface.
	AffineY() BaseFieldElementType
}
