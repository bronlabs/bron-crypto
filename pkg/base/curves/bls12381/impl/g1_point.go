package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.PointPtr[*Fp, *G1Point] = (*G1Point)(nil)
)

type G1Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, g1CurveParams, G1CurveHasherParams, g1CurveMapper, Fp]
