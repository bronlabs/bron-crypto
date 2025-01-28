package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

type PallasPoint = pointsImpl.ShortWeierstrassPointImpl[*Fp, pallasCurveParams, PallasCurveHasherParams, pallasCurveMapper, Fp]
