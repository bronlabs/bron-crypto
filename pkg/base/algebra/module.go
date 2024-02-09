package algebra

// AbstractModule defines methods needed for group ST to be considered as a module over the ring R.
// A module (ST, ScalarMult, (R, +, *)), is a structure defined over the ring (R, +, *) where (ST, +) is a commutiative group
// and ScalarMult distributes wrt +, has the same identity element as *, and ScalarMult(r*s, x) = ScalarMult(r, ScalarMult(s, x)) and
// vice versa.
type AbstractModule[ST Structure, M, S Element, R EnrichedElement[AbstractModuleBaseRing[ST, S]]] interface {
	// Module forms a group.

	AbstractGroup[ST, M]
	// Scalar returns an unspecified element of the base ring of ST.
	Scalar() S
	// ScalarRing returns the base ring of ST.
	ScalarRing() R
	// MultiScalarMult accepts ScalarMult(scs[i], es[i]) for all i of the provided input.
	MultiScalarMult(scs []S, es []M) (M, error)
}

// AbstractModuleBaseRing defines methods needed for the base ring of the module ST.
type AbstractModuleBaseRing[ST Structure, S Element] interface {
	// Base Ring is a Ring.
	AbstractRing[ST, S]
}

// AbstractModuleElement defines methods needed for elements of type M to be considered elements
// of module ST.
type AbstractModuleElement[ST Structure, M, S Element] interface {
	// Module elements are group elements.
	AbstractGroupElement[ST, M]

	// Mul returns scalar multiplication of this element and the input.
	ScalarMul(sc S) M
}

// AbstractModuleScalar defines methods needed for the elements of the basefield of ST.
type AbstractModuleScalar[ST Structure, S Element] interface {
	// Module Scalar is a Ring element.
	AbstractRingElement[ST, S]
}

// AbstractOneDimensionalModule defines methods needed for the module ST to be one dimensional.
// A one dimensional module ST forms a cyclic group under (ST, +).
// We assume some fixed generator is previously agreed upon.
type AbstractOneDimensionalModule[ST Structure, M, S Element, F EnrichedElement[AbstractModuleBaseRing[ST, S]]] interface {
	// One dimensional module is a module.
	AbstractModule[ST, M, S, F]
	// One dimensional module is a group.
	AbstractCyclicGroup[ST, M]
	// ScalarBaseMult returns scalar multiplication of the input with the generator of the module.
	ScalarBaseMult(sc S) M
}

// AbstractVector space defines methods needed for module ST where base ring is a field.
type AbstractVectorSpace[ST Structure, V, S Element, F EnrichedElement[AbstractVectorSpaceBaseField[ST, S]]] interface {
	// Vector space is a module.
	AbstractModule[ST, V, S, F]
	// ScalarField returns the base field of ST.
	ScalarField() F
}

// AbstractVectorSpaceBaseField defines methods needed for the base field of the vector space ST.
type AbstractVectorSpaceBaseField[ST Structure, S Element] interface {
	AbstractFiniteField[ST, S]
}

// AbstractVector defines methods needed for elements of type V to be elements of vector space ST.
type AbstractVector[ST Structure, V, S Element] interface {
	// Vector is a module element.
	AbstractModuleElement[ST, V, S]
}

// AbstractVectorSpaceScalar defines methods needed for the elements of the basfield of the vector space ST.
type AbstractVectorSpaceScalar[ST Structure, S Element] interface {
	// Vector space scalar is a finite field element.
	AbstractFiniteFieldElement[ST, S]
}

// AbstractOneDimensionalVectorSpace defines methods needed for a one dimensional module ST to be a vector space.
// We assume some fixed generator is previously agreed upon ie. the basis set is fixed.
type AbstractOneDimensionalVectorSpace[ST Structure, V, S Element, F EnrichedElement[AbstractVectorSpaceBaseField[ST, S]]] interface {
	// One dimensional vector space is a vector space.
	AbstractVectorSpace[ST, V, S, F]
	// One dimensional vector space forms a cyclic group.
	AbstractCyclicGroup[ST, V]
	// ScalarBaseMult returns scalar multiplication of the input with the generator of the vector space.
	ScalarBaseMult(sc S) V
}

type AbstractAlgebra[ST Structure, V, S Element, F EnrichedElement[AbstractVectorSpaceBaseField[ST, S]]] interface {
	AbstractVectorSpace[ST, V, S, F]
}

type AbstractAlgebraElement[ST Structure, V, S Element] interface {
	AbstractVector[ST, V, S]
	Prod(rhs V) V
}
