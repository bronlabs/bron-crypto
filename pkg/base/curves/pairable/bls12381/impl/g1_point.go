package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.Point[*Fp, *G1Point] = (*G1Point)(nil)
)

type G1Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, g1CurveParams, G1CurveHasherParams, g1CurveMapper, Fp]
