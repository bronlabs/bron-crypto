package bigint

import "github.com/copperexchange/krypton-primitives/pkg/base/integer"

type PositiveNumbers struct {
	integer.NPlus[*PositiveNumbers, *PositiveNatMixin]
}
