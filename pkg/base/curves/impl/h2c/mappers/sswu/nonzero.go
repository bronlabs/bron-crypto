package sswu

import (
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

type NonZeroPointMapperParams[FP fieldsImpl.FiniteField[FP]] interface {
	MulByA(out, in FP)
	MulByB(out, in FP)
	SetZ(out FP)
	SqrtRatio(out, u, v FP) (ok uint64)
	Sgn0(v FP) uint64
}

type NonZeroPointMapper[FP fieldsImpl.FiniteFieldPtrConstraint[FP, F], P NonZeroPointMapperParams[FP], F any] struct{}

func (NonZeroPointMapper[FP, P, F]) Map(xnOut, xdOut, ynOut, ydOut, u FP) {
	var params P
	sswu[FP](xnOut, ynOut, params, u)
	xdOut.SetOne()
	ydOut.SetOne()
}
