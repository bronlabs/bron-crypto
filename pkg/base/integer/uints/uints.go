package uints

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/uints/bigint"
)

type (
	Zn   = integer.Zn[bigint.Zn, bigint.Uint]
	Uint = integer.Uint[bigint.Zn, bigint.Uint]
)
