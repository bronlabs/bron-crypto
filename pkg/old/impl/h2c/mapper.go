package h2c

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
)

type PointMapper[FP fieldsImpl.FiniteField[FP]] interface {
	Map(xnOut, xdOut, ynOut, ydOut, u FP)
}
