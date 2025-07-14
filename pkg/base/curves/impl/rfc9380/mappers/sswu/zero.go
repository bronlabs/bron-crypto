package sswu

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
)

type ZeroPointMapperParams[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any] interface {
	NonZeroPointMapperParams[FP]
	XNum() []F
	XDen() []F
	YNum() []F
	YDen() []F
}

type ZeroPointMapper[FP fieldsImpl.FiniteFieldElementPtr[FP, F], P ZeroPointMapperParams[FP, F], F any] struct{}

func (ZeroPointMapper[FP, P, F]) Map(xnOut, xdOut, ynOut, ydOut, u *F) {
	var params P
	var isoX, isoY F
	sswu[FP](&isoX, &isoY, params, u)
	mapIso[FP](xnOut, xdOut, ynOut, ydOut, params, &isoX, &isoY)
}
