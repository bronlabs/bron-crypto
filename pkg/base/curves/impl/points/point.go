package points

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type ellipticPoint[FP impl.FiniteFieldElement[FP], PP impl.GroupElement[PP]] interface {
	impl.GroupElement[PP]
	Encode(dstPrefix string, message []byte)
	Hash(dstPrefix string, message []byte)

	SetRandom(prng io.Reader) (ok ct.Bool)
	SetGenerator()
	ClearCofactor(in PP)
	SetAffine(x, y FP) (ok ct.Bool)
	ToAffine(x, y FP) (ok ct.Bool)
}

type Point[FP impl.FiniteFieldElement[FP], PP ellipticPoint[FP, PP]] interface {
	ellipticPoint[FP, PP]
}
type PointPtr[FP impl.FiniteFieldElement[FP], PP ellipticPoint[FP, PP], P any] interface {
	*P
	ellipticPoint[FP, PP]
}
