package points

import (
	"io"

	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

type pointPtr[FP fieldsImpl.FiniteFieldPtr[FP], PP any] interface {
	Encode(dstPrefix string, message []byte)
	Hash(dstPrefix string, message []byte)

	Set(p PP)
	SetRandom(prng io.Reader) (ok uint64)
	SetIdentity()
	SetGenerator()
	SetAffine(x, y FP) (ok uint64)
	Select(choice uint64, z, nz PP)
	ClearCofactor(in PP)

	Add(lhs, rhs PP)
	Sub(lhs, rhs PP)
	Neg(v PP)
	Double(v PP)

	IsIdentity() uint64
	Equals(v PP) uint64

	ToAffine(x, y FP) (ok uint64)
}

type PointPtr[FP fieldsImpl.FiniteFieldPtr[FP], PP pointPtr[FP, PP]] interface {
	pointPtr[FP, PP]
}

type PointPtrConstraint[FP fieldsImpl.FiniteFieldPtr[FP], PP pointPtr[FP, PP], P any] interface {
	*P
	pointPtr[FP, PP]
}
