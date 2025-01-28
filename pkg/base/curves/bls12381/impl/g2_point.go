package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.Point[*Fp2, *G2Point] = (*G2Point)(nil)
)

type G2Point = pointsImpl.ShortWeierstrassPointImpl[*Fp2, g2CurveParams, G2CurveHasherParams, g2CurveMapper, Fp2]
