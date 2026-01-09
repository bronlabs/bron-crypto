package sswu

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// NonZeroPointMapperParams provides curve-specific helpers for SSWU.
type NonZeroPointMapperParams[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	// MulByA multiplies by the curve A parameter.
	MulByA(out, in FP)
	// MulByB multiplies by the curve B parameter.
	MulByB(out, in FP)
	// SetZ sets the SSWU Z parameter.
	SetZ(out FP)
	// SqrtRatio computes sqrt(u/v) with curve-specific parameters.
	SqrtRatio(out, u, v FP) (ok ct.Bool)
	// Sgn0 returns the sign bit per RFC 9380.
	Sgn0(v FP) ct.Bool
}

// NonZeroPointMapper maps field elements using SSWU without an isogeny.
type NonZeroPointMapper[FP fieldsImpl.FiniteFieldElementPtr[FP, F], P NonZeroPointMapperParams[FP], F any] struct{}

// Map maps u to a curve point represented by rational coordinates.
func (NonZeroPointMapper[FP, P, F]) Map(xnOut, xdOut, ynOut, ydOut, u FP) {
	var params P
	sswu[FP](xnOut, ynOut, params, u)
	xdOut.SetOne()
	ydOut.SetOne()
}
