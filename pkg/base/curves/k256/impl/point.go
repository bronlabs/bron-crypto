package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.PointPtr[*Fp, *Point] = (*Point)(nil)
)

type Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, curveParams, CurveHasherParams, curveMapper, Fp]
