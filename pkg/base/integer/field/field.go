package field

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/field/bigint"
)

type (
	Zp   = integer.Zp[bigint.Zp, bigint.IntP]
	IntP = integer.IntP[bigint.Zp, bigint.IntP]
)
