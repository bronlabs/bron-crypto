package algebra

// ****************** Module
// === Interfaces

type Module[M Group[M, ME, OpAdd], UR Rng[UR, S, UOpAdd, UOpMul], ME ModuleElement[ME, S], S RngElement[S], OpAdd Addition[ME], UOpAdd Addition[S], UOpMul Multiplication[S]] interface {
	SuperStructure[M, UR, ME, OpAdd]
	AbelianGroup[M, ME, OpAdd]
	GroupalAdditiveness[ME]
}

type ModuleElement[ME GroupElement[ME], S RngElement[S]] interface {
	AbelianGroupElement[ME]
	GroupElementalAdditiveness[ME]
	ScalarMul(sc S) ME
}

type UnitalModule[M Module[M, UR, ME, S, OpAdd, UOpAdd, UOpMul], UR Ring[UR, S, UOpAdd, UOpMul], ME ModuleElement[ME, S], S RingElement[S], OpAdd Addition[ME], UOpAdd Addition[S], UOpMul Multiplication[S]] interface {
	Module[M, UR, ME, S, OpAdd, UOpAdd, UOpMul]
}

type UnitalModuleElement[ME GroupElement[ME], S RingElement[S]] interface {
	ModuleElement[ME, S]
}

// === Aspects

type MultiScalarMult[ME ModuleElement[ME, S], S RngElement[S]] func(scs []S, es []ME) (ME, error)

type StructuralOneDimentionality[E, S any] interface {
	StructuralCyclicness[E]
	ScalarBaseMul(sc S) E
}

type ElementalOneDimensionality interface {
	ElementalCyclicness
}

// ****************** Vector Space
// === Interfaces

type VectorSpace[VS Module[VS, UF, V, S, OpAdd, UOpAdd, UOpMul], UF Field[UF, S, UOpAdd, UOpMul], V Vector[V, S], S FieldElement[S], OpAdd Addition[V], UOpAdd Addition[S], UOpMul Multiplication[S]] interface {
	UnitalModule[VS, UF, V, S, OpAdd, UOpAdd, UOpMul]
}

type Vector[ME ModuleElement[ME, S], S FieldElement[S]] interface {
	UnitalModuleElement[ME, S]
}
