package points

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type ellipticPoint[FP impl.FiniteFieldElementLowLevel[FP], PP impl.FiniteGroupElementLowLevel[PP]] interface {
	impl.FiniteGroupElementLowLevel[PP]
	Encode(dstPrefix string, message []byte)
	Hash(dstPrefix string, message []byte)

	SetGenerator()
	ClearCofactor(in PP)
	SetAffine(x, y FP) (ok ct.Bool)
	ToAffine(x, y FP) (ok ct.Bool)
}

// Point describes an elliptic curve point with encoding and hashing helpers.
type Point[FP impl.FiniteFieldElementLowLevel[FP], PP ellipticPoint[FP, PP]] interface {
	ellipticPoint[FP, PP]
}

// PointPtr is a pointer constraint for elliptic curve points.
type PointPtr[FP impl.FiniteFieldElementLowLevel[FP], PP ellipticPoint[FP, PP], P any] interface {
	*P
	ellipticPoint[FP, PP]
}
