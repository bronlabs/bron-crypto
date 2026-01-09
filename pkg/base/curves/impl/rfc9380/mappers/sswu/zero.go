package sswu

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
)

// ZeroPointMapperParams provides parameters for SSWU mapping with isogenies.
type ZeroPointMapperParams[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any] interface {
	NonZeroPointMapperParams[FP]
	// XNum returns isogeny x numerator coefficients.
	XNum() []F
	// XDen returns isogeny x denominator coefficients.
	XDen() []F
	// YNum returns isogeny y numerator coefficients.
	YNum() []F
	// YDen returns isogeny y denominator coefficients.
	YDen() []F
}

// ZeroPointMapper maps field elements using SSWU and an isogeny.
type ZeroPointMapper[FP fieldsImpl.FiniteFieldElementPtr[FP, F], P ZeroPointMapperParams[FP, F], F any] struct{}

// Map maps u to a curve point represented by rational coordinates.
func (ZeroPointMapper[FP, P, F]) Map(xnOut, xdOut, ynOut, ydOut, u *F) {
	var params P
	var isoX, isoY F
	sswu[FP](&isoX, &isoY, params, u)
	mapIso[FP](xnOut, xdOut, ynOut, ydOut, params, &isoX, &isoY)
}
