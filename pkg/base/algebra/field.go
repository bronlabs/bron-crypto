package algebra

import "github.com/cronokirby/saferith"

// AbstractFiniteField defines methods needed for S to be considered as a finite field.
// A finite field (S, +, *) is a positive characteristic ring where (S, *) is a group.
type AbstractFiniteField[S Structure, E Element] interface {
	// Field is a ring.
	AbstractRing[S, E]
	// Finite field has methods of a multiplicative group.
	MultiplicativeGroupTrait[S, E]
	// FieldBytes returns the **exact** number of bytes required to represent a FieldElement, required for `SetBytes()`
	FieldBytes() int
	// WideFieldBytes returns the **maximum** number of bytes required to map uniformly to a FieldElement, required for `SetBytesWide()`
	WideFieldBytes() int
}

// AbstractFiniteFieldElement defines methods needed for elements of type E to be members of field S.
// A finite field (S, +, *) is a positive characteristic ring where (S, *) is a group.
type AbstractFiniteFieldElement[S Structure, E Element] interface {
	// A field element is a ring element.
	AbstractRingElement[S, E]
	// A field element has methods of a multiplicative group element.
	MultiplicativeGroupElementTrait[S, E]
	// Exp returns the value of this element raised to the power of the input.
	// Specific implementations are dependent on S and E, but they should all reduce to
	// iterative multiplication for integer inputs.
	Exp(x E) E
	BytesLike[E]
}

// FieldExtensionTrait defines additional methods needed for field S to be considered extension of
// some smaller field.
// S extends field K if it forms a K-vector space.
type FieldExtensionTrait[S Structure, E, BaseE Element] interface {
	// ExtensionDegree returns the dimension S/K.
	ExtensionDegree() *saferith.Nat
	// FrobeniusAutomorphism returns the value of e raised to the power of characteristic of S.
	FrobeniusAutomorphism(e E) E
	// Trace returns the trace of linear transformation x*e where 1 <= x <= extension degree.
	Trace(e E) BaseE
}

// FieldExtensionElementTrait defines additional methods needed for elements of type E to be considered
// an element of field extension S.
type FieldExtensionElementTrait[E, SubE Element] interface {
	// Norm returns determinant of the linear transformation this*x in the vector space formed by S and its basefield.
	// e.g. in a quadratic field extension of a finite field output is this * this.Conjugate()
	Norm() SubE
	// SubFieldElement returns a field element in F_p, a subfield of F_{p^k} depending on its extension degree k:
	//  - For k>1 (with subfields F_{p_1}, ..., F_{p_k}), the element of F_{p_((i+1)%k)}.
	//  - For k=1, the element itself (in F_p already) regardless of i.
	SubFieldElement(i uint) SubE
}
