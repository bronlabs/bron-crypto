package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/points"
)

var (
	_ pointsImpl.Point[*Fp, *Point] = (*Point)(nil)
)

type Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, curveParams, CurveHasherParams, curveMapper, Fp]
