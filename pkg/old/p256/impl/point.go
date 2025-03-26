package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

type Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, curveParams, CurveHasherParams, curveMapper, Fp]
