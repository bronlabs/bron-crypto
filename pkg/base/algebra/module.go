package algebra

// Module defines methods needed for group ST to be considered as a module over the ring R.
// A module (ST, ScalarMult, (R, +, *)), is a structure defined over the ring (R, +, *) where (ST, +) is a commutiative group
// and ScalarMult distributes wrt +, has the same identity element as *, and ScalarMult(r*s, x) = ScalarMult(r, ScalarMult(s, x)) and
// vice versa.
type Module[ModuleType, BaseRingType Structure, ModuleElementType, ScalarType Element] interface {
	// Module forms a group.
	AdditiveGroup[ModuleType, ModuleElementType]
	// MultiScalarMult accepts ScalarMult(scs[i], es[i]) for all i of the provided input.
	MultiScalarMult(scs []ScalarType, es []ModuleElementType) (ModuleElementType, error)
	// ScalarRing returns the base ring of ST.
	ModuleScalarRing() ModuleBaseRing[ModuleType, BaseRingType, ModuleElementType, ScalarType]
}

// ModuleBaseRing defines methods needed for the base ring of the module ST.
type ModuleBaseRing[ModuleType, BaseRingType Structure, ModuleElementType, ScalarType Element] interface {
	// Base Ring is a Ring.
	Ring[BaseRingType, ScalarType]

	Module() Module[ModuleType, BaseRingType, ModuleElementType, ScalarType]
}

// ModuleElement defines methods needed for elements of type M to be considered elements
// of module ST.
type ModuleElement[ModuleType, BaseRingType Structure, ModuleElementType, ScalarType Element] interface {
	// Module elements are group elements.
	AdditiveGroupElement[ModuleType, ModuleElementType]

	// ScalarMul returns scalar multiplication of this element and the input.
	ScalarMul(sc ModuleScalar[ModuleType, BaseRingType, ModuleElementType, ScalarType]) ModuleElementType
}

// ModuleScalar defines methods needed for the elements of the basefield of ST.
type ModuleScalar[ModuleType, BaseRingType Structure, ModuleElementType, ScalarType Element] interface {
	// Module Scalar is a Ring element.
	RingElement[BaseRingType, ScalarType]
}

// OneDimensionalModule defines methods needed for the module ST to be one dimensional.
// A one dimensional module ST forms a cyclic group under (ST, +).
// We assume some fixed generator is previously agreed upon.
type OneDimensionalModule[ModuleType, BaseRingType Structure, ModuleElementType, ScalarType Element] interface {
	// One dimensional module is a module.
	Module[ModuleType, BaseRingType, ModuleElementType, ScalarType]
	// One dimensional module is a group.
	CyclicGroup[ModuleType, ModuleElementType]
	// ScalarBaseMult returns scalar multiplication of the input with the generator of the module.
	ScalarBaseMult(sc ModuleScalar[ModuleType, BaseRingType, ModuleElementType, ScalarType]) ModuleElementType
}
