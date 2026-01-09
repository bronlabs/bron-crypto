package rfc9380

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
)

// PointMapper maps a field element to curve point fractions.
type PointMapper[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	// Map defines the Map operation.
	Map(xnOut, xdOut, ynOut, ydOut, u FP)
}
