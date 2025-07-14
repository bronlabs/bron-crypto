package rfc9380

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
)

type PointMapper[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	Map(xnOut, xdOut, ynOut, ydOut, u FP)
}
