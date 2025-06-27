package points

import (
	"io"

	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
)

type point[FP fieldsImpl.FiniteFieldElement[FP], PP any] interface {
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

	// === compatibility with algebra traits ===
	Op(lhs, rhs PP) // Add
	OpOp(out PP)    // Double
}

type Point[FP fieldsImpl.FiniteFieldElement[FP], PP point[FP, PP]] interface {
	point[FP, PP]
}

type PointPtrConstraint[FP fieldsImpl.FiniteFieldElement[FP], PP point[FP, PP], P any] interface {
	*P
	point[FP, PP]
}
