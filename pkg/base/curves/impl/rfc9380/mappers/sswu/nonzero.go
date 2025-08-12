package sswu

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type NonZeroPointMapperParams[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	MulByA(out, in FP)
	MulByB(out, in FP)
	SetZ(out FP)
	SqrtRatio(out, u, v FP) (ok ct.Bool)
	Sgn0(v FP) ct.Bool
}

type NonZeroPointMapper[FP fieldsImpl.FiniteFieldElementPtr[FP, F], P NonZeroPointMapperParams[FP], F any] struct{}

func (NonZeroPointMapper[FP, P, F]) Map(xnOut, xdOut, ynOut, ydOut, u FP) {
	var params P
	sswu[FP](xnOut, ynOut, params, u)
	xdOut.SetOne()
	ydOut.SetOne()
}
