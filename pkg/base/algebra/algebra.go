package algebra

type AssociativeAlgebra[RAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	Module[RAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	MultiplicativeGroupoid[RAlgebraType, ModuleElementType]
	AssociativeAlgebraScalarRing() AssociativeAlgebraScalarRing[RAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type AssociativeAlgebraElement[RAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	ModuleElement[RAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	MultiplicativeGroupoidElement[RAlgebraType, ModuleElementType]
}

type AssociativeAlgebraScalarRing[RAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	ModuleBaseRing[RAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	AssociativeAlgebra() AssociativeAlgebra[RAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type AssociativeAlgebraScalar[RAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	ModuleScalar[RAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type UnitalAlgebra[UnitalAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	AssociativeAlgebra[UnitalAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	MultiplicativeMonoid[UnitalAlgebraType, ModuleElementType]
	UnitalAlgebraScalarRing() UnitalAlgebraScalarRing[UnitalAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type UnitalAlgebraElement[UnitalAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	AssociativeAlgebraElement[UnitalAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	MultiplicativeMonoidElement[UnitalAlgebraType, ModuleElementType]
}

type UnitalAlgebraScalarRing[UnitalAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	AssociativeAlgebraScalarRing[UnitalAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	UnitalAlgebra() UnitalAlgebra[UnitalAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type UnitalAlgebraScalar[UnitalAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	AssociativeAlgebraScalar[UnitalAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type DivisionAlgebra[DivisionAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	UnitalAlgebra[DivisionAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	MultiplicativeGroup[DivisionAlgebraType, ModuleElementType]
	DivisionAlgebraScalarRing() DivisionAlgebraScalarRing[DivisionAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type DivisionAlgebraElement[DivisionAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	UnitalAlgebraElement[DivisionAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	MultiplicativeGroupElement[DivisionAlgebraType, ModuleElementType]
}

type DivisionAlgebraScalarRing[DivisionAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	UnitalAlgebraScalarRing[DivisionAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
	DivisionAlgebra() DivisionAlgebra[DivisionAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}

type DivisionAlgebraScalar[DivsionAlgebraType, ScalarRingType Structure, ModuleElementType, ScalarType Element] interface {
	UnitalAlgebraScalar[DivsionAlgebraType, ScalarRingType, ModuleElementType, ScalarType]
}
