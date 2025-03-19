package sswu

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
)

func mapIso[FP fieldsImpl.FiniteFieldElementPtrConstraint[FP, F], P ZeroPointMapperParams[FP, F], F any](xnOut, xdOut, ynOut, ydOut *F, params P, xIn, yIn *F) {
	var xNum, xDen, yNum, yDen F

	polyEval[FP](&xNum, params.XNum(), xIn)
	polyEval[FP](&xDen, params.XDen(), xIn)
	polyEval[FP](&yNum, params.YNum(), xIn)
	polyEval[FP](&yDen, params.YDen(), xIn)
	FP(&yNum).Mul(&yNum, yIn)

	FP(xnOut).Set(&xNum)
	FP(xdOut).Set(&xDen)
	FP(ynOut).Set(&yNum)
	FP(ydOut).Set(&yDen)
}

func polyEval[FP fieldsImpl.FieldElementPtrConstraint[FP, F], F any](result *F, coefficients []F, at *F) {
	FP(result).Set(&coefficients[len(coefficients)-1])
	for i := len(coefficients) - 2; i >= 0; i-- {
		FP(result).Mul(result, at)
		FP(result).Add(result, &coefficients[i])
	}
}
