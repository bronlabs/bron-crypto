package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.Point[*Fp, *Point] = (*Point)(nil)
)

// Point represents a curve point.
type Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, curveParams, CurveHasherParams, curveMapper, Fp]
