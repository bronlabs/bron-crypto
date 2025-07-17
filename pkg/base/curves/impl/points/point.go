package points

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
)

type (
	Point[FP impl.FiniteFieldElement[FP], PP impl.EllipticPoint[FP, PP]]                 = impl.EllipticPoint[FP, PP]
	PointPtr[FP impl.FiniteFieldElement[FP], PP impl.EllipticPointPtr[FP, PP, P], P any] = impl.EllipticPointPtr[FP, PP, P]
)
