package vectorspace

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/field"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/module"
)

type HolesVectorSpace[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] interface {
	module.HolesModule[VS, BF, V, S]
}

type HolesVector[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] interface {
	module.HolesModuleElement[VS, BF, V, S]
}

type HolesVectorSpaceBaseField[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] interface {
	module.HolesModuleBaseRing[VS, BF, V, S]
	field.HolesField[BF, S]
}

type HolesVectorSpaceScalar[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] interface {
	module.HolesModuleScalar[VS, BF, V, S]
	field.HolesFieldElement[BF, S]
}

type HolesOneDimensionalVectorSpace[VS algebra.OneDimensionalVectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.OneDimensionalVector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] interface {
	HolesVectorSpace[VS, BF, V, S]
	module.HolesOneDimensionalModule[VS, BF, V, S]
}

type HolesOneDimensionalVector[VS algebra.OneDimensionalVectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.OneDimensionalVector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] interface {
	HolesVector[VS, BF, V, S]
	module.HolesOneDimensionalModuleElement[VS, BF, V, S]
}

func NewVectorSpace[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]](H HolesVectorSpace[VS, BF, V, S], baseFieldConstructor func() BF) VectorSpace[VS, BF, V, S] {
	return VectorSpace[VS, BF, V, S]{
		Module: module.NewModule(H, baseFieldConstructor),
		_field: baseFieldConstructor,
		H:      H,
	}
}
func NewVector[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]](H HolesVector[VS, BF, V, S]) Vector[VS, BF, V, S] {
	return Vector[VS, BF, V, S]{
		ModuleElement: module.NewModuleElement(H),
		H:             H,
	}
}
func NewVectorSpaceBaseField[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]](H HolesVectorSpaceBaseField[VS, BF, V, S], vectorSpaceConstructor func() VS) VectorSpaceBaseField[VS, BF, V, S] {
	return VectorSpaceBaseField[VS, BF, V, S]{
		ModuleBaseRing: module.NewModuleBaseRing(H, vectorSpaceConstructor),
		Field:          field.NewField(H),
		H:              H,
	}
}

func NewVectorSpaceScalar[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]](H HolesVectorSpaceScalar[VS, BF, V, S]) VectorSpaceScalar[VS, BF, V, S] {
	return VectorSpaceScalar[VS, BF, V, S]{
		ModuleScalar: module.NewModuleScalar(H),
		FieldElement: field.NewFieldElement(H),
		H:            H,
	}
}

func NewOneDimensionalVectorSpace[VS algebra.OneDimensionalVectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.OneDimensionalVector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]](H HolesOneDimensionalVectorSpace[VS, BF, V, S], baseFieldConstructor func() BF) OneDimensionalVectorSpace[VS, BF, V, S] {
	return OneDimensionalVectorSpace[VS, BF, V, S]{
		VectorSpace:          NewVectorSpace(H, baseFieldConstructor),
		OneDimensionalModule: module.NewOneDimensionalModule(H, baseFieldConstructor),
		H:                    H,
	}
}

func NewOneDimensionalVector[VS algebra.OneDimensionalVectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.OneDimensionalVector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]](H HolesOneDimensionalVector[VS, BF, V, S]) OneDimensionalVector[VS, BF, V, S] {
	return OneDimensionalVector[VS, BF, V, S]{
		Vector:                      NewVector(H),
		OneDimensionalModuleElement: module.NewOneDimensionalModuleElement(H),
		H:                           H,
	}
}
