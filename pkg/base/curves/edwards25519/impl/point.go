package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

// Point represents a curve point.
type Point = pointsImpl.TwistedEdwardsPointImpl[*Fp, curveParams, CurveHasherParams, curveMapper, Fp]
