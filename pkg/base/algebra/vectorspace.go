package algebra

// AbstractVector space defines methods needed for module ST where base ring is a field.
type VectorSpace[VectorSpaceType, BaseFieldType Structure, VectorType, ScalarType Element] interface {
	// Vector space is a module.
	Module[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
	// ScalarField returns the base field of ST.
	VectorSpaceScalarField() VectorSpaceBaseField[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
}

// VectorSpaceBaseField defines methods needed for the base field of the vector space ST.
type VectorSpaceBaseField[VectorSpaceType, BaseFieldType Structure, VectorType, ScalarType Element] interface {
	ModuleBaseRing[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
	Field[BaseFieldType, ScalarType]

	VectorSpace() VectorSpace[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
}

// Vector defines methods needed for elements of type V to be elements of vector space ST.
type Vector[VectorSpaceType, BaseFieldType Structure, VectorType, ScalarType Element] interface {
	// Vector is a module element.
	ModuleElement[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
}

// VectorSpaceScalar defines methods needed for the elements of the basfield of the vector space ST.
type VectorSpaceScalar[VectorSpaceType, BaseFieldType Structure, VectorType, ScalarType Element] interface {
	// Vector space scalar is a finite field element.
	FieldElement[BaseFieldType, ScalarType]
}

// OneDimensionalVectorSpace defines methods needed for a one dimensional module ST to be a vector space.
// We assume some fixed generator is previously agreed upon ie. the basis set is fixed.
type OneDimensionalVectorSpace[VectorSpaceType, BaseFieldType Structure, VectorType, ScalarType Element] interface {
	VectorSpace[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
	OneDimensionalModule[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
}

type OneDimensionalVector[VectorSpaceType, BaseFieldType Structure, VectorType, ScalarType Element] interface {
	Vector[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
	OneDimensionalModuleElement[VectorSpaceType, BaseFieldType, VectorType, ScalarType]
}
