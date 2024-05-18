package vectorspace

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/field"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/module"
)

type VectorSpace[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] struct {
	module.Module[VS, BF, V, S]

	_field func() BF

	H HolesVectorSpace[VS, BF, V, S]
}

func (vs *VectorSpace[VS, BF, V, S]) VectorSpaceScalarField() algebra.VectorSpaceBaseField[VS, BF, V, S] {
	return vs._field()
}

type VectorSpaceBaseField[VS algebra.VectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.Vector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] struct {
	module.ModuleBaseRing[VS, BF, V, S]
	field.Field[BF, S]

	_vectorSpace func() VS

	H HolesVectorSpaceBaseField[VS, BF, V, S]
}

func (bf *VectorSpaceBaseField[VS, BF, V, S]) VectorSpace() algebra.VectorSpace[VS, BF, V, S] {
	return bf._vectorSpace()
}

type OneDimensionalVectorSpace[VS algebra.OneDimensionalVectorSpace[VS, BF, V, S], BF algebra.VectorSpaceBaseField[VS, BF, V, S], V algebra.OneDimensionalVector[VS, BF, V, S], S algebra.VectorSpaceScalar[VS, BF, V, S]] struct {
	VectorSpace[VS, BF, V, S]
	module.OneDimensionalModule[VS, BF, V, S]

	H HolesOneDimensionalVectorSpace[VS, BF, V, S]
}
