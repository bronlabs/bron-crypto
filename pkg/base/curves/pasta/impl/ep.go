package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

// PallasPoint represents a Pallas curve point.
type PallasPoint = pointsImpl.ShortWeierstrassPointImpl[*Fp, pallasCurveParams, PallasCurveHasherParams, pallasCurveMapper, Fp]
