package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
)

func NewEuclideanNormOperator[T crtp.EuclideanSemiDomainElement[T]](sort universal.Sort) (*universal.UnaryOperator[T], error) {
	return universal.NewUnaryOperator(
		sort, universal.UnaryFunctionSymbol("N"),
		func(v T) (T, error) {
			return v.EuclideanValuation(), nil
		},
	)
}

func NewLeftActionOperator[E crtp.Actable[E, S], S crtp.SemiGroupElement[S]](moduleSort, scalarSort universal.Sort) (*universal.LeftAction[S, E], error) {
	return universal.NewLeftAction(
		moduleSort, scalarSort, universal.DotSymbol,
		func(s S, e E) (E, error) {
			return e.ScalarOp(s), nil
		},
	)
}

func NewScalarMultiplicationOperator[E crtp.AdditivelyActable[E, S], S crtp.SemiGroupElement[S]](moduleSort, scalarSort universal.Sort) (*universal.LeftAction[S, E], error) {
	return universal.NewLeftAction(
		moduleSort, scalarSort, universal.DotSymbol,
		func(s S, e E) (E, error) {
			return e.ScalarMul(s), nil
		},
	)
}
