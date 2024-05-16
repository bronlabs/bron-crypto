package algebra

import "github.com/cronokirby/saferith"

type Field[F Structure, E Element] interface {
	// Field is a ring.
	EuclideanDomain[F, E]
	// Finite field has methods of a multiplicative group.
	MultiplicativeGroup[F, E]
}

type FieldElement[F Structure, E Element] interface {
	// A field element is a ring element.
	EuclideanDomainElement[F, E]
	// A field element has methods of a multiplicative group element.
	MultiplicativeGroupElement[F, E]
}

// FiniteField defines methods needed for S to be considered as a finite field.
// A finite field (S, +, *) is a positive characteristic ring where (S, *) is a group.
type FiniteField[FF Structure, E Element] interface {
	Field[FF, E]
	FiniteEuclideanDomain[FF, E]
}

// FiniteFieldElement defines methods needed for elements of type E to be members of field S.
// A finite field (S, +, *) is a positive characteristic ring where (S, *) is a group.
type FiniteFieldElement[FF Structure, E Element] interface {
	FieldElement[FF, E]
	FiniteEuclideanDomainElement[FF, E]
}

type ExtensionField[ExtendedFieldType, PrimeFieldType Structure, ExtendedFieldElementType, PrimeFieldElementType Element] interface {
	Field[ExtendedFieldType, ExtendedFieldElementType]
	// ExtensionDegree returns the dimension S/K.
	ExtensionDegree() *saferith.Nat
	// FrobeniusAutomorphism returns the value of e raised to the power of characteristic of S.
	FrobeniusAutomorphism(e ExtendedFieldElementType) PrimeFieldElementType
	// Trace returns the trace of linear transformation x*e where 1 <= x <= extension degree.
	Trace(e ExtendedFieldElementType) PrimeFieldElementType
}

type ExtensionFieldElement[ExtendedFieldType, PrimeFieldType Structure, ExtendedFieldElementType, PrimeFieldElementType Element] interface {
	FieldElement[ExtendedFieldType, ExtendedFieldElementType]
	// SubFieldElement returns a field element in F_p, a subfield of F_{p^k} depending on its extension degree k:
	//  - For k>1 (with subfields F_{p_1}, ..., F_{p_k}), the element of F_{p_((i+1)%k)}.
	//  - For k=1, the element itself (in F_p already) regardless of i.
	SubFieldElement(i uint) (PrimeFieldElementType, error)
	// Norm returns determinant of the linear transformation this*x in the vector space formed by S and its basefield.
	// eg. in a quadratic field extension of a finite field output is this * this.Conjugate()
	Norm() PrimeFieldElementType
	Conjugate() PrimeFieldElementType
}
