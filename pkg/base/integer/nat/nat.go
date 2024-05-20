package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/nat/bigint"
)

type (
	N   = integer.N[bigint.N, bigint.Nat]
	Nat = integer.Nat[bigint.N, bigint.Nat]
)
