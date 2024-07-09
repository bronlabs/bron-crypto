package algebra

import "github.com/cronokirby/saferith"

// === Interfaces

type AlgebraicVariety[V Space[V, VE], BF Field[BF, BFE, BOpAdd, BOpMul], VE AlgebraicVarietyElement[VE], BFE FieldElement[BFE], BOpAdd Addition[BFE], BOpMul Multiplication[BFE]] interface {
	SuperSpace[V, BF, VE]
	// Discriminant returns some number as function of its coefficients. The exact definition is context dependent.
	// eg. for elliptic curves it would be -16(4a^3+27b^2)
	Discriminant() *saferith.Int
	// FrobeniusEndomorphism returns an element whose coordinates are coordinates of p, each raised to the power of characteristic of the base field.
	FrobeniusEndomorphism(p VE) VE
}

type AlgebraicVarietyElement[VE Element[VE]] interface {
	Element[VE]
}

type AlgebraicGroup[G Group[G, GE, Op], BF Field[BF, BFE, BOpAdd, BOpMul], GE AlgebraicGroupElement[GE, BFE], BFE FieldElement[BFE], Op BinaryOperator[GE], BOpAdd Addition[BFE], BOpMul Multiplication[BFE]] interface {
	SuperStructure[G, BF, GE, Op]
	Group[G, GE, Op]
	AlgebraicVariety[G, BF, GE, BFE, BOpAdd, BOpMul]
}

type AlgebraicGroupElement[GE GroupElement[GE], BFE FieldElement[BFE]] interface {
	GroupElement[GE]
	AlgebraicVarietyElement[GE]
}

type AlgebraicCurve[C AlgebraicVariety[C, BF, P, BFE, BOpAdd, BOpMul], BF Field[BF, BFE, BOpAdd, BOpMul], P Point[P, BFE], BFE FieldElement[BFE], BOpAdd Addition[BFE], BOpMul Multiplication[BFE]] interface {
	AlgebraicVariety[C, BF, P, BFE, BOpAdd, BOpMul]
	StructuralAffineness
	NewPoint(affineX, affineY BFE) (P, error)
}

type Point[P AlgebraicVarietyElement[P], BFE FieldElement[BFE]] interface {
	AlgebraicVarietyElement[P]
	ElementalAffineness[P, BFE]
	AffineX() BFE
	AffineY() BFE
}

// === Aspects

type StructuralAffineness any

type ElementalAffineness[E, BFE any] interface {
	// AffineCoordinates return an ordered slice of field elements that are the coordinates of the point implementing this interface.
	AffineCoordinates() []BFE
	// ToAffineCompressed returns the compressed affine serialisation of this element.
	ToAffineCompressed() []byte
	// ToAffineUncompressed returns the uncompressed affine serialisation of this element.
	ToAffineUncompressed() []byte
	// FromAffineCompressed returns the element represented by the compressed affine serialisation.
	FromAffineCompressed(bytes []byte) (E, error)
	// FromAffineUncompressed returns the element represented by the uncompressed affine serialisation.
	FromAffineUncompressed(bytes []byte) (E, error)
}
