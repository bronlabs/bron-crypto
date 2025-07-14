package points

import (
	"io"

	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type point[FP fieldsImpl.FiniteFieldElement[FP], PP any] interface {
	ct.ConditionallyAssignable[PP]
	Encode(dstPrefix string, message []byte)
	Hash(dstPrefix string, message []byte)

	Set(p PP)
	SetRandom(prng io.Reader) (ok ct.Bool)
	SetIdentity()
	SetGenerator()
	SetAffine(x, y FP) (ok ct.Bool)
	ClearCofactor(in PP)

	Add(lhs, rhs PP)
	Sub(lhs, rhs PP)
	Neg(v PP)
	Double(v PP)

	IsIdentity() ct.Bool
	Equals(v PP) ct.Bool

	ToAffine(x, y FP) (ok ct.Bool)
}

type Point[FP fieldsImpl.FiniteFieldElement[FP], PP point[FP, PP]] interface {
	point[FP, PP]
}

type PointPtr[FP fieldsImpl.FiniteFieldElement[FP], PP point[FP, PP], P any] interface {
	*P
	point[FP, PP]
}
