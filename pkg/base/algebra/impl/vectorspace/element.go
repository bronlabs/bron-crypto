package vectorspace

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/field"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/module"
)

type Vector[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] struct {
	module.ModuleElement[VS, BF, V, S]

	H HolesVector[VS, BF, V, S]
}

type VectorSpaceScalar[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] struct {
	module.ModuleScalar[VS, BF, V, S]
	field.FieldElement[BF, S]

	H HolesVectorSpaceScalar[VS, BF, V, S]
}

type OneDimensionalVector[VS algebra.OneDimensionalVectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.OneDimensionalVector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] struct {
	Vector[VS, BF, V, S]
	module.OneDimensionalModuleElement[VS, BF, V, S]

	H HolesOneDimensionalVector[VS, BF, V, S]
}
