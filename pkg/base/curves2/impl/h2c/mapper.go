package h2c

import (
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/fields"
)

type PointMapper[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	Map(xnOut, xdOut, ynOut, ydOut, u FP)
}
