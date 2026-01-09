package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

// VestaPoint represents a Vesta curve point.
type VestaPoint = pointsImpl.ShortWeierstrassPointImpl[*Fq, vestaCurveParams, VestaCurveHasherParams, vestaCurveMapper, Fq]
