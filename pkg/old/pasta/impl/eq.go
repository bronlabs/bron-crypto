package impl

import (
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

type VestaPoint = pointsImpl.ShortWeierstrassPointImpl[*Fq, vestaCurveParams, VestaCurveHasherParams, vestaCurveMapper, Fq]
