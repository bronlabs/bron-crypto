package impl

import (
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

type VestaPoint = pointsImpl.ShortWeierstrassPointImpl[*Fq, vestaCurveParams, VestaCurveHasherParams, vestaCurveMapper, Fq]
