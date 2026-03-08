package mat_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
)

func _[E algebra.ModuleElement[E, S], S algebra.RingElement[S]]() {
	var (
		_ algebra.MatrixModule[*mat.Matrix[S], S] = (*mat.MatrixModule[S])(nil)
		_ algebra.Matrix[*mat.Matrix[S], S]       = (*mat.Matrix[S])(nil)

		_ algebra.MatrixAlgebra[*mat.SquareMatrix[S], S] = (*mat.MatrixAlgebra[S])(nil)
		_ algebra.SquareMatrix[*mat.SquareMatrix[S], S]  = (*mat.SquareMatrix[S])(nil)

		_ algebra.Module[*mat.ModuleValuedMatrix[E, S], S]        = (*mat.ModuleValuedMatrixModule[E, S])(nil)
		_ algebra.ModuleElement[*mat.ModuleValuedMatrix[E, S], S] = (*mat.ModuleValuedMatrix[E, S])(nil)

		_ algebra.FiniteStructure[*mat.Matrix[S]]                = (*mat.MatrixModule[S])(nil)
		_ algebra.FiniteStructure[*mat.SquareMatrix[S]]          = (*mat.MatrixAlgebra[S])(nil)
		_ algebra.FiniteStructure[*mat.ModuleValuedMatrix[E, S]] = (*mat.ModuleValuedMatrixModule[E, S])(nil)
	)
}
