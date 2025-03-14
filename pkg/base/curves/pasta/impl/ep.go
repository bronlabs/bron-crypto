package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

type PallasPoint = pointsImpl.ShortWeierstrassPointImpl[*Fp, pallasCurveParams, PallasCurveHasherParams, pallasCurveMapper, Fp]
