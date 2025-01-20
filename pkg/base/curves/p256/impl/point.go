package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

type Point = pointsImpl.ShortWeierstrassPointImpl[*Fp, curveParams, CurveHasherParams, curveMapper, Fp]
